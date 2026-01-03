package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Layr-Labs/vtls-agent/internal/config"
	"github.com/Layr-Labs/vtls-agent/internal/vtls"
)

const (
	bundlePath = "/.well-known/vtls/v1/bundle"

	maxEnvelopeBytes = 8 << 20 // 8 MiB
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.FromEnv()
	if err != nil {
		logger.Error("config error", "err", err)
		os.Exit(1)
	}

	mnemonic := strings.TrimSpace(os.Getenv("MNEMONIC"))
	keys, err := vtls.DeriveKeysFromMnemonic(mnemonic)
	if err != nil {
		logger.Error("key derivation error", "err", err)
		os.Exit(1)
	}

	cache := vtls.NewBundleCache(keys, cfg.BundleTTL)

	h := &handler{
		logger: logger,
		cfg:    cfg,
		keys:   keys,
		cache:  cache,
		client: &http.Client{Timeout: 60 * time.Second},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(bundlePath, h.handleBundle)
	mux.HandleFunc("/", h.handleRoot)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("vtls-agent listening",
		"addr", cfg.ListenAddr,
		"upstream", cfg.Upstream.String(),
		"mode", cfg.Mode,
		"app_address", keys.AppAddress,
	)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

type handler struct {
	logger *slog.Logger
	cfg    *config.Config
	keys   *vtls.Keys
	cache  *vtls.BundleCache
	client *http.Client
}

func (h *handler) handleBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	domain, origin := h.domainAndOrigin(r)
	now := time.Now()

	b, _, err := h.cache.Get(domain, origin, now)
	if err != nil {
		h.logger.Error("bundle generation error", "err", err)
		writeError(w, http.StatusInternalServerError, "bundle_error", "failed to generate bundle")
		return
	}

	// Cache bundles for their full TTL. Browsers should re-fetch shortly before expiry.
	maxAge := int(h.cfg.BundleTTL.Seconds())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_ = json.NewEncoder(w).Encode(b)
}

func (h *handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == bundlePath {
		h.handleBundle(w, r)
		return
	}

	protected, stripPrefix := h.isProtected(r.URL.Path)
	if !protected {
		h.proxyPlaintext(w, r, false, stripPrefix)
		return
	}
	h.proxyProtected(w, r, stripPrefix)
}

func (h *handler) isProtected(path string) (protected bool, stripPrefix bool) {
	switch h.cfg.Mode {
	case config.ModeOff, config.ModeBundleOnly:
		return false, false
	case config.ModeAll:
		return true, false
	case config.ModeVTLSPrefix:
		if strings.HasPrefix(path, h.cfg.VTLSPrefix+"/") || path == h.cfg.VTLSPrefix {
			return true, true
		}
		return false, false
	case config.ModeProtectPrefixes:
		for _, p := range h.cfg.ProtectPrefixes {
			if strings.HasPrefix(path, p) {
				return true, false
			}
		}
		// Also treat /vtls prefix as protected if configured, for the "dual surface" rollout.
		if strings.HasPrefix(path, h.cfg.VTLSPrefix+"/") || path == h.cfg.VTLSPrefix {
			return true, true
		}
		return false, false
	default:
		return false, false
	}
}

func (h *handler) proxyPlaintext(w http.ResponseWriter, r *http.Request, force bool, stripPrefix bool) {
	_ = force

	upURL, err := h.makeUpstreamURL(r, stripPrefix)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_url_error", "invalid upstream URL")
		return
	}

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upURL.String(), r.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_request_error", "failed to create upstream request")
		return
	}
	copyHeaders(upReq.Header, r.Header)
	upReq.Host = h.cfg.Upstream.Host

	resp, err := h.client.Do(upReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_unreachable", "failed to reach upstream")
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (h *handler) proxyProtected(w http.ResponseWriter, r *http.Request, stripPrefix bool) {
	// Parse envelope JSON.
	body, err := readBodyLimited(r.Body, maxEnvelopeBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	var env vtls.EnvelopeV1
	if err := json.Unmarshal(body, &env); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_envelope", "invalid JSON envelope")
		return
	}

	bundleHash32, requestID, clientEphPub32, nonce12, ciphertext, err := vtls.DecodeEnvelopeFieldsV1(&env)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_envelope", err.Error())
		return
	}

	domain, origin := h.domainAndOrigin(r)
	b, expectedHash32, err := h.cache.Get(domain, origin, time.Now())
	if err != nil {
		h.logger.Error("bundle cache error", "err", err)
		writeError(w, http.StatusInternalServerError, "bundle_error", "failed to load bundle")
		return
	}
	if subtle.ConstantTimeCompare(bundleHash32, expectedHash32[:]) != 1 {
		_ = b // bundle exists, but hash mismatch
		writeError(w, http.StatusBadRequest, "bundle_hash_mismatch", "bundle_hash does not match current bundle")
		return
	}

	clientPub, err := ecdh.X25519().NewPublicKey(clientEphPub32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_envelope", "invalid client_ephemeral_pubkey")
		return
	}
	key32, err := vtls.DeriveSymmetricKeyV1(h.keys.EncPriv, clientPub, bundleHash32)
	if err != nil {
		h.logger.Error("kdf error", "err", err)
		writeError(w, http.StatusBadRequest, "crypto_error", "failed to derive key")
		return
	}

	// Bind decryption to the outer HTTP request method/path.
	plaintext, err := vtls.DecryptRequestV1(key32, r.Method, r.URL.Path, bundleHash32, requestID, nonce12, ciphertext)
	if err != nil {
		writeError(w, http.StatusBadRequest, "decrypt_failed", "failed to decrypt request")
		return
	}

	// Proxy plaintext to upstream.
	upResp, upBody, err := h.proxyToUpstream(w, r, plaintext, true, stripPrefix, true, bundleHash32, requestID)
	if err != nil {
		// proxyToUpstream already wrote error response (plaintext) for network issues
		return
	}

	// Encrypt response back to browser (same derived key, fresh nonce).
	respNonce, respCT, err := vtls.EncryptResponseV1(key32, upResp.StatusCode, r.Method, r.URL.Path, bundleHash32, requestID, upBody)
	if err != nil {
		h.logger.Error("encrypt error", "err", err)
		writeError(w, http.StatusInternalServerError, "encrypt_failed", "failed to encrypt response")
		return
	}

	respEnv := vtls.EnvelopeV1{
		Version:              vtls.ProtocolVersionV1,
		BundleHash:           env.BundleHash,
		RequestID:            env.RequestID,
		ClientEphemeralPubKey: env.ClientEphemeralPubKey,
		Nonce:               base64.StdEncoding.EncodeToString(respNonce),
		Ciphertext:          base64.StdEncoding.EncodeToString(respCT),
	}

	digest := vtls.ResponseSignatureDigestV1(respCT, upResp.StatusCode, r.Method, r.URL.Path, bundleHash32, requestID)
	sig, err := vtls.SignCompactDigestV1(h.keys.SigPriv, digest[:])
	if err != nil {
		h.logger.Error("sign error", "err", err)
		writeError(w, http.StatusInternalServerError, "sign_failed", "failed to sign response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-VTLS", "1")
	w.Header().Set("X-VTLS-Signature", base64.StdEncoding.EncodeToString(sig))
	w.Header().Set("X-VTLS-Bundle-Hash", env.BundleHash)
	w.Header().Set("X-VTLS-Request-Id", env.RequestID)
	w.WriteHeader(upResp.StatusCode)
	_ = json.NewEncoder(w).Encode(respEnv)
}

func (h *handler) proxyToUpstream(w http.ResponseWriter, r *http.Request, body []byte, isProtected bool, stripPrefix bool, wantBody bool, bundleHash32, requestID []byte) (*http.Response, []byte, error) {
	upURL, err := h.makeUpstreamURL(r, stripPrefix)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_url_error", "invalid upstream URL")
		return nil, nil, err
	}

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	} else {
		reqBody = r.Body
	}
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upURL.String(), reqBody)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_request_error", "failed to create upstream request")
		return nil, nil, err
	}
	upReq.Host = h.cfg.Upstream.Host

	// Minimal headers. (We intentionally do not forward arbitrary client headers in v1.)
	if isProtected {
		upReq.Header.Set("Content-Type", "application/octet-stream")
		upReq.Header.Set("X-VTLS-Request", "1")
		upReq.Header.Set("X-VTLS-Bundle-Hash", base64.StdEncoding.EncodeToString(bundleHash32))
		upReq.Header.Set("X-VTLS-Request-Id", base64.StdEncoding.EncodeToString(requestID))
	}

	resp, err := h.client.Do(upReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_unreachable", "failed to reach upstream")
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_read_error", "failed to read upstream response")
		return nil, nil, err
	}

	if !wantBody {
		return resp, nil, nil
	}
	return resp, respBody, nil
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func isHopByHopHeader(k string) bool {
	switch strings.ToLower(k) {
	case "connection",
		"proxy-connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailer",
		"transfer-encoding",
		"upgrade":
		return true
	default:
		return false
	}
}

func (h *handler) makeUpstreamURL(r *http.Request, stripPrefix bool) (*url.URL, error) {
	// Use the inbound path/query, optionally stripping the vtls prefix for the upstream app.
	path := r.URL.Path
	if stripPrefix {
		if path == h.cfg.VTLSPrefix {
			path = "/"
		} else if strings.HasPrefix(path, h.cfg.VTLSPrefix+"/") {
			path = strings.TrimPrefix(path, h.cfg.VTLSPrefix)
			if path == "" {
				path = "/"
			}
		}
	}
	ref := &url.URL{Path: path, RawQuery: r.URL.RawQuery}
	return h.cfg.Upstream.ResolveReference(ref), nil
}

func (h *handler) domainAndOrigin(r *http.Request) (domain string, origin string) {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = strings.TrimSpace(r.URL.Host)
	}
	host = stripPort(host)

	domain = host
	if h.cfg.DomainOverride != "" {
		domain = h.cfg.DomainOverride
	}

	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	origin = proto + "://" + domain
	return domain, origin
}

func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err == nil && h != "" {
		return h
	}
	// If SplitHostPort fails, host might have no port (or be an IPv6 literal without brackets).
	// In those cases, keep as-is.
	return host
}

func readBodyLimited(r io.Reader, max int64) ([]byte, error) {
	lr := io.LimitReader(r, max+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("body too large (max %d bytes)", max)
	}
	return b, nil
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var e apiError
	e.Error.Code = code
	e.Error.Message = msg
	_ = json.NewEncoder(w).Encode(e)
}


