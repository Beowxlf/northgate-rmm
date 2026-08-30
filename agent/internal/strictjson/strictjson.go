// Package strictjson rejects invalid UTF-8, duplicate object keys, malformed
// nesting, and trailing values before a caller decodes into a concrete schema.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

func Validate(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}
	if err := validateSurrogateEscapes(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := checkValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return fmt.Errorf("JSON contains trailing token %v", token)
	}
	return nil
}

func validateSurrogateEscapes(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(raw) {
				continue
			}
			if raw[index+1] != 'u' {
				index++
				continue
			}
			value, ok := escapedCodePoint(raw, index)
			if !ok {
				continue
			}
			if value >= 0xdc00 && value <= 0xdfff {
				return errors.New("JSON contains an unpaired low surrogate escape")
			}
			if value < 0xd800 || value > 0xdbff {
				index += 5
				continue
			}
			next := index + 6
			low, paired := escapedCodePoint(raw, next)
			if !paired || low < 0xdc00 || low > 0xdfff {
				return errors.New("JSON contains an unpaired high surrogate escape")
			}
			index = next + 5
		}
	}
	return nil
}

func escapedCodePoint(raw []byte, index int) (uint64, bool) {
	if index < 0 || index+6 > len(raw) || raw[index] != '\\' || raw[index+1] != 'u' {
		return 0, false
	}
	value, err := strconv.ParseUint(string(raw[index+2:index+6]), 16, 16)
	return value, err == nil
}

func checkValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	var closing json.Delim
	switch delimiter {
	case '{':
		closing = '}'
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := checkValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		closing = ']'
		for decoder.More() {
			if err := checkValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	actual, err := decoder.Token()
	if err != nil {
		return err
	}
	if actual != closing {
		return errors.New("mismatched JSON delimiter")
	}
	return nil
}
