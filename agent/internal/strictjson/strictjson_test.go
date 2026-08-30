package strictjson

import "testing"

func TestValidateSurrogateEscapes(t *testing.T) {
	valid := [][]byte{
		[]byte(`{"value":"plain"}`),
		[]byte(`{"value":"\ud83d\ude00"}`),
		[]byte(`{"value":"😀"}`),
	}
	for _, raw := range valid {
		if err := Validate(raw); err != nil {
			t.Fatalf("Validate(%s) error = %v", raw, err)
		}
	}
	invalid := [][]byte{
		[]byte(`{"value":"\ud800"}`),
		[]byte(`{"value":"\ud800x"}`),
		[]byte(`{"value":"\udc00"}`),
		[]byte(`{"\ud800":"value"}`),
	}
	for _, raw := range invalid {
		if err := Validate(raw); err == nil {
			t.Fatalf("Validate(%s) accepted an unpaired surrogate", raw)
		}
	}
}

func FuzzValidate(f *testing.F) {
	f.Add([]byte(`{"value":"\ud83d\ude00"}`))
	f.Add([]byte(`{"value":"\ud800"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = Validate(raw)
	})
}
