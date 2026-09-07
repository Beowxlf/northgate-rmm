// Package remote probes the local native desktop backend without credentials,
// shell execution, or accepting network destinations from remote input.
package remote

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// DesktopReady verifies an RDP negotiation response on the fixed local port.
// It does not authenticate, create a desktop session, or change OS settings.
func DesktopReady(ctx context.Context) bool {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:3389")
	if err != nil {
		return false
	}
	defer connection.Close()
	if connection.SetDeadline(time.Now().Add(3*time.Second)) != nil {
		return false
	}
	request := []byte{3, 0, 0, 19, 14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}
	if _, err := connection.Write(request); err != nil {
		return false
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return false
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if header[0] != 3 || header[1] != 0 || length < 19 || length > 1024 {
		return false
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(connection, body); err != nil {
		return false
	}
	return body[1] == 0xd0 && body[7] == 2 && body[9] == 8
}
