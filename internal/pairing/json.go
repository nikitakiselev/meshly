package pairing

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// maxJSONDepth bounds nesting of decoded JSON.
const maxJSONDepth = 8

// strictUnmarshal decodes exactly one JSON object into v: unknown fields,
// duplicate keys, excessive nesting and trailing data are rejected so that
// two parsers can never disagree about the content.
func strictUnmarshal(data []byte, v any) error {
	if err := checkJSON(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// checkJSON validates structure: a single top-level object, no duplicate
// keys at any level, bounded depth, no trailing data.
func checkJSON(data []byte) error {
	type frame struct {
		obj       bool
		keys      map[string]struct{}
		expectKey bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("top-level value must be an object")
	}
	stack := []*frame{{obj: true, keys: map[string]struct{}{}, expectKey: true}}
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].obj {
			stack[n-1].expectKey = true
		}
	}
	for len(stack) > 0 {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON: %v", err)
		}
		top := stack[len(stack)-1]
		if top.obj && top.expectKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				valueDone()
				continue
			}
			k, ok := tok.(string)
			if !ok {
				return errors.New("object key must be a string")
			}
			// encoding/json matches field names case-insensitively, so
			// "INVITE_ID" would silently alias "invite_id": only canonical
			// keys are accepted.
			if !canonicalKey(k) {
				return fmt.Errorf("non-canonical key %q", truncateStr(k))
			}
			if _, dup := top.keys[k]; dup {
				return fmt.Errorf("duplicate key %q", truncateStr(k))
			}
			top.keys[k] = struct{}{}
			top.expectKey = false
			continue
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) >= maxJSONDepth {
					return errors.New("JSON nesting too deep")
				}
				f := &frame{obj: d == '{', expectKey: d == '{'}
				if f.obj {
					f.keys = map[string]struct{}{}
				}
				stack = append(stack, f)
			case ']', '}':
				stack = stack[:len(stack)-1]
				valueDone()
			}
			continue
		}
		valueDone()
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON object")
	}
	return nil
}

func canonicalKey(k string) bool {
	if k == "" || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func truncateStr(s string) string {
	if r := []rune(s); len(r) > 64 {
		return string(r[:64]) + "…"
	}
	return s
}
