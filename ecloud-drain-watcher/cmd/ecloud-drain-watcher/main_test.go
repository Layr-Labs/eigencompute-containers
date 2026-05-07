package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDrainRequested(t *testing.T) {
	t.Run("returns true when metadata body is 1 and sends metadata header", func(t *testing.T) {
		var gotHeader string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotHeader = r.Header.Get("Metadata-Flavor")
			_, _ = w.Write([]byte("1\n"))
		}))
		defer ts.Close()
		w := newWatcher("ECLOUD_DRAIN_REQUESTED", 1, time.Millisecond, time.Second, nil, nil)
		w.metadataURL = ts.URL
		got, err := w.drainRequested(context.Background())
		require.NoError(t, err)
		assert.True(t, got)
		assert.Equal(t, "Google", gotHeader)
	})

	t.Run("returns false for missing metadata", func(t *testing.T) {
		ts := httptest.NewServer(http.NotFoundHandler())
		defer ts.Close()
		w := newWatcher("ECLOUD_DRAIN_REQUESTED", 1, time.Millisecond, time.Second, nil, nil)
		w.metadataURL = ts.URL
		got, err := w.drainRequested(context.Background())
		require.NoError(t, err)
		assert.False(t, got)
	})

	t.Run("returns false for 0", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("0")) }))
		defer ts.Close()
		w := newWatcher("ECLOUD_DRAIN_REQUESTED", 1, time.Millisecond, time.Second, nil, nil)
		w.metadataURL = ts.URL
		got, err := w.drainRequested(context.Background())
		require.NoError(t, err)
		assert.False(t, got)
	})
}

func TestRunSignalsPID(t *testing.T) {
	called := false
	signaledPID := 0
	var signaled syscall.Signal
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("1")) }))
	defer ts.Close()

	out := &strings.Builder{}
	w := newWatcher("ECLOUD_DRAIN_REQUESTED", 42, time.Millisecond, time.Second, out, nil)
	w.metadataURL = ts.URL
	w.signal = func(pid int, sig syscall.Signal) error {
		called = true
		signaledPID = pid
		signaled = sig
		return nil
	}
	require.NoError(t, w.run(context.Background()))
	assert.True(t, called)
	assert.Equal(t, 42, signaledPID)
	assert.Equal(t, syscall.SIGTERM, signaled)
	assert.Contains(t, out.String(), "signaling PID 42")
}

func TestRunStopsOnContextCancel(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	w := newWatcher("ECLOUD_DRAIN_REQUESTED", 1, time.Hour, time.Second, nil, nil)
	w.metadataURL = ts.URL
	w.sleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return ctx.Err()
	}
	err := w.run(ctx)
	require.ErrorIs(t, err, context.Canceled)
}
