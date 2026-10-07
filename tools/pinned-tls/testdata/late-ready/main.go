// Test-only IPC peer. It reports READY after expiry, without connecting anywhere
// or enforcing expiry itself, so the parent's pre-IPC check is tested in isolation.
package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"time"
)

func main() {
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
		ExpiresAt int64 `json:"expiresAt"`
	}
	if json.Unmarshal(data, &config) != nil || config.ExpiresAt <= 0 {
		return
	}
	time.Sleep(time.Until(time.UnixMilli(config.ExpiresAt).Add(100 * time.Millisecond)))
	if _, err := os.Stdout.Write([]byte{2, 0, 0, 0, 0}); err != nil {
		return
	}
	// Reading the frame header alone proves whether any REQUEST was handed over;
	// never parse, echo or retain the synthetic credentials or body.
	if _, err := io.ReadFull(os.Stdin, head[:]); err != nil || head[0] != 3 {
		return
	}
	code := []byte("TEE_REQUEST_REJECTED")
	head[0] = 7
	binary.BigEndian.PutUint32(head[1:], uint32(len(code)))
	_, _ = os.Stdout.Write(append(head[:], code...))
}
