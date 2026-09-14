package management

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

func TestToolOutputDecodesRedirectedUnicodeBeforeSerialization(t *testing.T) {
	want := "Autoruns ©\r\n\"Name\",\"Publisher\"\r\n\"工具\",\"Example 😀\"\r\n"
	for _, little := range []bool{true, false} {
		var order binary.ByteOrder = binary.BigEndian
		data := []byte{0xfe, 0xff}
		if little {
			order = binary.LittleEndian
			data = []byte{0xff, 0xfe}
		}
		for _, unit := range utf16.Encode([]rune(want)) {
			var encoded [2]byte
			order.PutUint16(encoded[:], unit)
			data = append(data, encoded[:]...)
		}
		got, truncated := decodeToolOutput(string(data), 4096)
		if truncated || got != want || strings.ContainsRune(got, '\x00') {
			t.Fatalf("incorrect redirected text: %q", got)
		}
		got, truncated = decodeToolOutput(string(data), 53)
		if !truncated || len(got) > 53 || !utf8.ValidString(got) {
			t.Fatal("decoded output escaped its byte budget")
		}
	}
	got, truncated := decodeToolOutput("plain UTF-8 😀", 100)
	if truncated || got != "plain UTF-8 😀" {
		t.Fatal("UTF-8 output was modified")
	}
	got, _ = decodeToolOutput("\xff\xfeA\x00B", 100)
	if got != "A\ufffd" {
		t.Fatal("incomplete UTF-16 unit was silently discarded")
	}
}

func utf16LETestBytes(text string) string {
	data := make([]byte, 0, len(text)*2)
	for _, unit := range utf16.Encode([]rune(text)) {
		data = append(data, byte(unit), byte(unit>>8))
	}
	return string(data)
}

func TestSysinternalsBOMlessCSVPreservesUnicodeBeforeJSON(t *testing.T) {
	// The observed Sigcheck pipe begins P\0a\0t\0h\0,\0V\0e\0r\0...
	// with no BOM. Use synthetic rows, not workstation inventory, in fixtures.
	want := "Path,Verified,Date,Publisher\r\n\"C:\\Ops\\工具😀.exe\",\"Signed\",\"2026-09-10\",\"Example © ™\"\r\n"
	raw := utf16LETestBytes(want)
	for _, prefix := range []string{"", "\xff\xfe"} {
		got, truncated := decodeWindowsToolOutput("sysinternals", prefix+raw, 4096)
		if got != want || truncated || strings.ContainsAny(got, "\x00\ufffd") {
			t.Fatalf("UTF-16 CSV was not decoded intact: %q", got)
		}
		serialized, err := json.Marshal(map[string]string{"output": got})
		var receipt map[string]string
		if err != nil || json.Unmarshal(serialized, &receipt) != nil || receipt["output"] != want {
			t.Fatal("decoded Unicode did not survive the receipt JSON boundary")
		}
	}
}

func TestSysinternalsBOMlessCSVRetainsByteBudget(t *testing.T) {
	want := "Path,Verified,Publisher\r\n" + strings.Repeat("工具😀©™", 100)
	raw := utf16LETestBytes(want)
	for _, limit := range []int{0, 1, 25, 27, 31, 100, 512} {
		got, truncated := decodeWindowsToolOutput("sysinternals", raw, limit)
		if !truncated || len(got) > limit || !utf8.ValidString(got) || strings.ContainsRune(got, '\ufffd') || !strings.HasPrefix(want, got) {
			t.Fatalf("UTF-8 expansion exceeded or corrupted byte budget %d", limit)
		}
	}
}

func TestSysinternalsBOMlessPartialUnitsAreVisible(t *testing.T) {
	prefix := "Path,Verified,Publisher\r\n"
	for _, suffix := range []string{"A", "\x3d\xd8"} {
		// One odd byte or an unmatched high surrogate is malformed UTF-16.
		got, truncated := decodeWindowsToolOutput("sysinternals", utf16LETestBytes(prefix)+suffix, 4096)
		if got != prefix+"\ufffd" || truncated {
			t.Fatal("incomplete UTF-16 was silently dropped or exceeded the budget")
		}
	}
}

func TestSysinternalsInferenceDoesNotReinterpretUTF8OrOtherTools(t *testing.T) {
	for _, raw := range []string{"Path,Verified,Publisher\r\nUTF-8 工具 😀 ©", "plain\x00UTF-8", "P\x00a\x00t\x00h", "ASCII prefix " + utf16LETestBytes("Path,Verified")} {
		want, _ := decodeToolOutput(raw, 4096)
		got, truncated := decodeWindowsToolOutput("sysinternals", raw, 4096)
		if got != want || truncated {
			t.Fatal("plain/mixed UTF-8 or insufficient prefix was reinterpreted")
		}
	}
	raw := utf16LETestBytes("Path,Verified,Publisher\r\nSynthetic only")
	for _, tool := range []string{"osquery", "yara-x", "velociraptor"} {
		got, truncated := decodeWindowsToolOutput(tool, raw, 4096)
		if got != raw || truncated {
			t.Fatal("UTF-16 inference escaped the Sysinternals adapter")
		}
	}
}
