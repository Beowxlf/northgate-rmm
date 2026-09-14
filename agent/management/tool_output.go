package management

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// Sigcheck with -nobanner omits the UTF-16LE BOM. Infer that encoding only for
// the approved Sysinternals recipe, whose redirected CSV has an ASCII header.
// Other tools can legitimately emit UTF-8 containing NULs; do not reinterpret
// those bytes merely because they resemble UTF-16.
func decodeWindowsToolOutput(toolID, raw string, maximum int) (string, bool) {
	if toolID == "sysinternals" && hasUTF16LETextPrefix(raw) {
		raw = "\xff\xfe" + raw
	}
	return decodeToolOutput(raw, maximum)
}

func hasUTF16LETextPrefix(raw string) bool {
	// Eight complete printable ASCII units are enough to recognize the fixed
	// CSV header without sampling paths/publishers which can contain Unicode.
	if len(raw) < 16 {
		return false
	}
	for i := 0; i < 16; i += 2 {
		if raw[i+1] != 0 || raw[i] < 0x20 || raw[i] > 0x7e {
			return false
		}
	}
	return true
}

// Decode before JSON serialization replaces invalid UTF-8 bytes irreversibly.
func decodeToolOutput(raw string, maximum int) (string, bool) {
	decoded := raw
	if strings.HasPrefix(raw, "\xff\xfe") || strings.HasPrefix(raw, "\xfe\xff") {
		var order binary.ByteOrder = binary.LittleEndian
		if strings.HasPrefix(raw, "\xfe\xff") {
			order = binary.BigEndian
		}
		data := []byte(raw[2:])
		units := make([]uint16, len(data)/2)
		for i := range units {
			units[i] = order.Uint16(data[i*2 : i*2+2])
		}
		decoded = string(utf16.Decode(units))
		if len(data)%2 != 0 {
			decoded += "\ufffd"
		}
	} else {
		decoded = strings.ToValidUTF8(raw, "\ufffd")
	}
	if len(decoded) > maximum {
		// An output budget is in bytes, including UTF-8 expansion. Do not leave
		// a partial multibyte character at the boundary.
		return strings.ToValidUTF8(decoded[:maximum], ""), true
	}
	return decoded, false
}
