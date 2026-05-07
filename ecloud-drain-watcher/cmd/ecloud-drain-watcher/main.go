package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

var (
	version = "dev"
	commit  = "unknown"
)

type signalFunc func(pid int, sig syscall.Signal) error

type watcher struct {
	metadataURL    string
	pollInterval   time.Duration
	requestTimeout time.Duration
	signalPID      int
	client         *http.Client
	signal         signalFunc
	stdout         io.Writer
	stderr         io.Writer
	sleep          func(context.Context, time.Duration) error
}

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	metadataKey := flag.String("metadata-key", "ECLOUD_DRAIN_REQUESTED", "GCE instance metadata key to poll")
	signalPID := flag.Int("signal-pid", 1, "PID to signal when drain is requested")
	pollInterval := flag.Duration("poll-interval", 2*time.Second, "metadata poll interval")
	requestTimeout := flag.Duration("request-timeout", 2*time.Second, "per-request timeout")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ecloud-drain-watcher %s (commit %s)\n", version, commit)
		return
	}

	w := newWatcher(*metadataKey, *signalPID, *pollInterval, *requestTimeout, os.Stdout, os.Stderr)
	if err := w.run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "ecloud-drain-watcher: %v\n", err)
		os.Exit(1)
	}
}

func newWatcher(metadataKey string, signalPID int, pollInterval, requestTimeout time.Duration, stdout, stderr io.Writer) *watcher {
	metadataKey = strings.TrimSpace(metadataKey)
	if metadataKey == "" {
		metadataKey = "ECLOUD_DRAIN_REQUESTED"
	}
	if signalPID <= 0 {
		signalPID = 1
	}
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	if requestTimeout <= 0 {
		requestTimeout = 2 * time.Second
	}
	return &watcher{
		metadataURL:    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/" + metadataKey,
		pollInterval:   pollInterval,
		requestTimeout: requestTimeout,
		signalPID:      signalPID,
		client:         &http.Client{Timeout: requestTimeout},
		signal:         syscall.Kill,
		stdout:         stdout,
		stderr:         stderr,
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
	}
}

func (w *watcher) run(ctx context.Context) error {
	for {
		requested, err := w.drainRequested(ctx)
		if err != nil && w.stderr != nil {
			fmt.Fprintf(w.stderr, "ecloud-drain-watcher: metadata poll failed: %v\n", err)
		}
		if requested {
			if w.stdout != nil {
				fmt.Fprintf(w.stdout, "ecloud-drain-watcher: saw drain request, signaling PID %d\n", w.signalPID)
			}
			return w.signal(w.signalPID, syscall.SIGTERM)
		}
		if err := w.sleep(ctx, w.pollInterval); err != nil {
			return err
		}
	}
}

func (w *watcher) drainRequested(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.metadataURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := w.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		return false, fmt.Errorf("metadata HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(body)) == "1", nil
}
