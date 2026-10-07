package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenerateFixture(t *testing.T) {
	dir := os.Getenv("PI_TEE_TLS_TEST_FIXTURE_DIR")
	if dir == "" {
		t.Skip("Synthetic Node/Bun fixture generation was not requested")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("Fixture directory must be absolute")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"key.pem":  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func inputFrame(t *testing.T, kind byte, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 5+len(data))
	frame[0] = kind
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(data)))
	copy(frame[5:], data)
	return frame
}

func outputFrame(t *testing.T, r io.Reader) (byte, []byte) {
	t.Helper()
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(head[1:])
	if size > 65536 {
		t.Fatalf("Oversized output: %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		t.Fatal(err)
	}
	return head[0], data
}

func fixture(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	digest := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	return server, hex.EncodeToString(digest[:])
}

func TestPinPrecedesRequestAndOnlyOneHTTPDispatch(t *testing.T) {
	var sends atomic.Int32
	server, pin := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-key" {
			t.Error("Missing synthetic key")
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "synthetic request" {
			t.Error("Wrong synthetic body")
		}
		w.Header().Set("Location", serverPlaceholder)
		w.WriteHeader(307)
		_, _ = w.Write([]byte("redirect body"))
	})
	for _, value := range []string{hex.EncodeToString(make([]byte, 32)), pin} {
		input := bytes.NewReader(append(inputFrame(t, frameInit, configuration{Endpoint: server.URL + "/v1/chat/completions", Fingerprint: value}), inputFrame(t, frameRequest, requestData{Headers: map[string]string{"Authorization": "Bearer synthetic-key"}, Body: []byte("synthetic request")})...))
		var out bytes.Buffer
		keepOpen, finish := io.Pipe()
		err := run(io.MultiReader(input, keepOpen), &out)
		_ = finish.Close()
		_ = keepOpen.Close()
		if value != pin {
			if err != errKey {
				t.Fatalf("Bad pin: %v", err)
			}
			if sends.Load() != 0 || out.Len() != 0 {
				t.Fatal("A rejected pin must neither dispatch nor announce readiness")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			kind, _ := outputFrame(t, &out)
			if kind != frameReady {
				t.Fatal("Expected handshake readiness first")
			}
			kind, body := outputFrame(t, &out)
			var response responseData
			if kind != frameResponse || json.Unmarshal(body, &response) != nil || response.Status != 307 {
				t.Fatal("Redirect must be returned, not followed")
			}
			kind, body = outputFrame(t, &out)
			if kind != frameBody || string(body) != "redirect body" {
				t.Fatal("Response body lost")
			}
			kind, _ = outputFrame(t, &out)
			if kind != frameEnd || out.Len() != 0 || sends.Load() != 1 {
				t.Fatal("Expected exactly one dispatch")
			}
		}
	}
}

const serverPlaceholder = "https://must-never-be-contacted.invalid/"

func TestRequestIsNotReadBeforeAttestedHandshake(t *testing.T) {
	server, _ := fixture(t, func(http.ResponseWriter, *http.Request) { t.Error("Unexpected request") })
	first := inputFrame(t, frameInit, configuration{Endpoint: server.URL + "/v1/chat/completions", Fingerprint: hex.EncodeToString(make([]byte, 32))})
	reader := &gateReader{Reader: bytes.NewReader(first), t: t}
	if err := run(reader, io.Discard); err != errKey {
		t.Fatalf("Wrong result: %v", err)
	}
}

type gateReader struct {
	*bytes.Reader
	t *testing.T
}

func (r *gateReader) Read(p []byte) (int, error) {
	if r.Len() == 0 {
		r.t.Fatal("Read credential/payload channel before key check")
	}
	return r.Reader.Read(p)
}

func TestMalformedOrOversizedInputFailsWithoutDispatch(t *testing.T) {
	server, pin := fixture(t, func(http.ResponseWriter, *http.Request) { t.Error("Unexpected request") })
	good := configuration{Endpoint: server.URL + "/v1/chat/completions", Fingerprint: pin}
	for _, endpoint := range []string{"http://untrusted.invalid/v1/chat/completions", server.URL + "/wrong", server.URL + "/v1/chat/completions?other"} {
		if err := run(bytes.NewReader(inputFrame(t, frameInit, configuration{Endpoint: endpoint, Fingerprint: pin})), io.Discard); err != errInput {
			t.Fatalf("Invalid endpoint: %v", err)
		}
	}
	large := []byte{frameRequest, 255, 255, 255, 255}
	if err := run(bytes.NewReader(append(inputFrame(t, frameInit, good), large...)), io.Discard); err != errInput {
		t.Fatalf("Oversize: %v", err)
	}
	malformed := append(inputFrame(t, frameInit, good), inputFrame(t, frameRequest, map[string]any{"body": "AA==", "headers": map[string]string{}, "unknown": true})...)
	if err := run(bytes.NewReader(malformed), io.Discard); err != errInput {
		t.Fatalf("Unexpected fields: %v", err)
	}
}

func TestEOFClosesStreamingSocket(t *testing.T) {
	closed := make(chan struct{})
	server, pin := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("first"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(closed)
	})
	inputRead, inputWrite := io.Pipe()
	outputRead, outputWrite := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- run(inputRead, outputWrite); _ = outputWrite.Close() }()
	go func() {
		_, _ = inputWrite.Write(inputFrame(t, frameInit, configuration{Endpoint: server.URL + "/v1/chat/completions", Fingerprint: pin}))
		kind, _ := outputFrame(t, outputRead)
		if kind != frameReady {
			t.Error("Not ready")
		}
		_, _ = inputWrite.Write(inputFrame(t, frameRequest, requestData{Body: []byte("synthetic")}))
		kind, _ = outputFrame(t, outputRead)
		if kind != frameResponse {
			t.Error("No response")
		}
		kind, _ = outputFrame(t, outputRead)
		if kind != frameBody {
			t.Error("No delta")
		}
		_ = inputWrite.Close()
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("EOF did not cancel the remote request")
	}
	_ = outputRead.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Helper did not stop")
	}
}

func TestExpiryAfterHandshakePreventsHTTP(t *testing.T) {
	var sends atomic.Int32
	server, pin := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		w.WriteHeader(200)
	})
	inputRead, inputWrite := io.Pipe()
	outputRead, outputWrite := io.Pipe()
	defer inputRead.Close()
	defer inputWrite.Close()
	defer outputRead.Close()
	defer outputWrite.Close()
	done := make(chan error, 1)
	go func() { done <- run(inputRead, outputWrite) }()
	config := map[string]any{"endpoint": server.URL + "/v1/chat/completions", "fingerprint": pin, "expiresAt": time.Now().Add(time.Second).UnixMilli()}
	go func() { _, _ = inputWrite.Write(inputFrame(t, frameInit, config)) }()
	ready := make(chan byte, 1)
	go func() {
		var header [5]byte
		if _, err := io.ReadFull(outputRead, header[:]); err != nil {
			ready <- 0
			return
		}
		ready <- header[0]
	}()
	select {
	case err := <-done:
		t.Fatalf("Initialization rejected before readiness: %v", err)
	case kind := <-ready:
		if kind != frameReady {
			t.Fatal("Handshake did not finish")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Readiness timed out")
	}
	time.Sleep(1100 * time.Millisecond)
	_, _ = inputWrite.Write(inputFrame(t, frameRequest, requestData{Headers: map[string]string{"Authorization": "Bearer synthetic-key"}, Body: []byte("synthetic")}))
	select {
	case err := <-done:
		if err == nil || err.Error() != "TEE_PUBLIC_SESSION_REJECTED" {
			t.Fatalf("Wrong expiry result: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Expiry did not terminate dispatch")
	}
	if sends.Load() != 0 {
		t.Fatal("Expired admission leaked HTTP credentials or payload")
	}
}
