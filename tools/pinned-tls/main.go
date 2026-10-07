package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	frameInit     byte = 1
	frameReady    byte = 2
	frameRequest  byte = 3
	frameResponse byte = 4
	frameBody     byte = 5
	frameEnd      byte = 6
	frameError    byte = 7
	maxBody            = 16 * 1024 * 1024
	maxControl         = 64 * 1024
	maxRequest         = maxBody*4/3 + maxControl
)

var (
	errInput      = errors.New("TEE_REQUEST_REJECTED")
	errKey        = errors.New("TEE_TLS_KEY_REJECTED")
	errConnection = errors.New("TEE_CONNECTION_FAILED")
	errExpired    = errors.New("TEE_PUBLIC_SESSION_REJECTED")
)

type configuration struct {
	Endpoint    string `json:"endpoint"`
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   *int64 `json:"expiresAt,omitempty"`
}

type requestData struct {
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

type responseData struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
}

func readFrame(in io.Reader, kind byte, limit uint32, value any) error {
	var head [5]byte
	if _, err := io.ReadFull(in, head[:]); err != nil {
		return errInput
	}
	size := binary.BigEndian.Uint32(head[1:])
	if head[0] != kind || size == 0 || size > limit {
		return errInput
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(in, data); err != nil {
		return errInput
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errInput
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errInput
	}
	return nil
}

func writeFrame(out io.Writer, kind byte, data []byte) error {
	var head [5]byte
	head[0] = kind
	binary.BigEndian.PutUint32(head[1:], uint32(len(data)))
	if _, err := out.Write(head[:]); err != nil {
		return errConnection
	}
	if len(data) > 0 {
		if _, err := out.Write(data); err != nil {
			return errConnection
		}
	}
	return nil
}

func writeJSON(out io.Writer, kind byte, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > maxControl {
		return errConnection
	}
	return writeFrame(out, kind, data)
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

func run(in io.Reader, out io.Writer) error {
	var config configuration
	if err := readFrame(in, frameInit, maxControl, &config); err != nil {
		return err
	}
	target, err := url.Parse(config.Endpoint)
	pin, pinErr := hex.DecodeString(config.Fingerprint)
	if err != nil || pinErr != nil || len(pin) != 32 || config.Fingerprint != strings.ToLower(config.Fingerprint) ||
		target.Scheme != "https" || target.Hostname() == "" || target.User != nil || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" ||
		target.EscapedPath() != "/v1/chat/completions" || target.Opaque != "" || (config.ExpiresAt != nil && (*config.ExpiresAt <= 0 || *config.ExpiresAt > 9007199254740991)) {
		return errInput
	}
	port := target.Port()
	if port == "" {
		port = "443"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target.Hostname(), port), 10*time.Second)
	if err != nil {
		return errConnection
	}
	defer conn.Close()
	// Attested SPKI is the authorization root. Complete and authenticate the
	// same TLS socket before reading headers or payload from the parent pipe.
	secure := tls.Client(conn, &tls.Config{ServerName: target.Hostname(), MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	defer secure.Close()
	_ = secure.SetDeadline(time.Now().Add(10 * time.Second))
	if secure.Handshake() != nil {
		return errConnection
	}
	certificates := secure.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return errKey
	}
	digest := sha256.Sum256(certificates[0].RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(digest[:], pin) != 1 {
		return errKey
	}
	_ = secure.SetDeadline(time.Time{})
	if err := writeFrame(out, frameReady, nil); err != nil {
		return err
	}
	var data requestData
	if err := readFrame(in, frameRequest, maxRequest, &data); err != nil {
		return err
	}
	if len(data.Body) > maxBody {
		return errInput
	}
	request, err := http.NewRequest("POST", config.Endpoint, bytes.NewReader(data.Body))
	if err != nil {
		return errInput
	}
	headerBytes := 0
	for name, value := range data.Headers {
		headerBytes += len(name) + len(value) + 4
		if headerBytes > maxControl || !validHeaderName(name) || strings.ContainsAny(value, "\r\n\x00") {
			return errInput
		}
		switch strings.ToLower(name) {
		case "host", "connection", "content-length", "transfer-encoding", "trailer", "expect", "proxy-authorization", "proxy-connection", "upgrade":
			return errInput
		}
		request.Header.Set(name, value)
	}
	request.Close = true
	// No HTTP Client/Transport: they may redirect, reconnect, retry or pool.
	// Write precisely once to the socket whose attested key was checked above.
	if config.ExpiresAt != nil && time.Now().UnixMilli() >= *config.ExpiresAt {
		return errExpired
	}
	if request.Write(secure) != nil {
		return errConnection
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		var trailing [1]byte
		_, _ = in.Read(trailing[:])
		select {
		case <-done:
			return
		default:
			_ = conn.Close()
		}
	}()
	reader := bufio.NewReaderSize(secure, 32768)
	var head []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return errConnection
		}
		head = append(head, b)
		if len(head) > maxControl {
			return errConnection
		}
		if bytes.HasSuffix(head, []byte("\r\n\r\n")) {
			break
		}
	}
	response, err := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(head), reader)), request)
	if err != nil || response.StatusCode < 200 || response.StatusCode > 599 {
		return errConnection
	}
	defer response.Body.Close()
	if err := writeJSON(out, frameResponse, responseData{Status: response.StatusCode, Headers: response.Header}); err != nil {
		return err
	}
	chunk := make([]byte, 32768)
	for {
		n, err := response.Body.Read(chunk)
		if n > 0 {
			if failure := writeFrame(out, frameBody, chunk[:n]); failure != nil {
				return failure
			}
		}
		if err == io.EOF {
			return writeFrame(out, frameEnd, nil)
		}
		if err != nil {
			return errConnection
		}
	}
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		// Fixed codes only: never echo transport errors, headers or payloads.
		_ = writeFrame(os.Stdout, frameError, []byte(err.Error()))
		os.Exit(1)
	}
}
