// Test-only IPC peer. It reports READY after expiry without enforcing expiry
// itself. A loopback observer records REQUEST independently of the parent's error.
package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"time"
)

func main() {
	if len(os.Args) == 1 {
		// The reader survives termination of the immediate helper so it can observe
		// an already-written REQUEST even if the parent throws straight afterward.
		child := exec.Command(os.Args[0], "observe")
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		_ = child.Run()
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "observe" {
		return
	}
	go func() {
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}()
	var head [5]byte
	if _, err := io.ReadFull(os.Stdin, head[:]); err != nil || head[0] != 1 {
		return
	}
	size := binary.BigEndian.Uint32(head[1:])
	if size == 0 || size > 65536 {
		return
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(os.Stdin, data); err != nil {
		return
	}
	var config struct {
		ExpiresAt int64  `json:"expiresAt"`
		Endpoint  string `json:"endpoint"`
	}
	if json.Unmarshal(data, &config) != nil || config.ExpiresAt <= 0 {
		return
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Hostname() != "127.0.0.1" || endpoint.Port() == "" {
		return
	}
	observer, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
	if err != nil {
		return
	}
	defer observer.Close()
	time.Sleep(time.Until(time.UnixMilli(config.ExpiresAt).Add(100 * time.Millisecond)))
	if _, err := os.Stdout.Write([]byte{2, 0, 0, 0, 0}); err != nil {
		return
	}
	// Reading the frame header alone proves whether any REQUEST was handed over;
	// never parse, echo or retain the synthetic credentials or body.
	if _, err := io.ReadFull(os.Stdin, head[:]); err == io.EOF {
		_, _ = observer.Write([]byte{0})
		return
	}
	_, _ = observer.Write([]byte{1}) // Any incoming bytes after READY are a failure.
	code := []byte("TEE_REQUEST_REJECTED")
	head[0] = 7
	binary.BigEndian.PutUint32(head[1:], uint32(len(code)))
	_, _ = os.Stdout.Write(append(head[:], code...))
}
