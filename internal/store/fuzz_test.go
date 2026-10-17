package store

import (
	"bytes"
	"testing"
)

func FuzzDecodeConfig(f *testing.F) {
	valid := encode(f, testConfig())
	noPeers := testConfig()
	noPeers.Peers, noPeers.Rules = nil, nil
	for _, seed := range [][]byte{
		valid,
		encode(f, noPeers),
		bytes.Join(bytes.Fields(valid), nil),
		append(append([]byte{}, valid...), valid...),
		bytes.Replace(valid, []byte(`"mtu": 1420`), []byte(`"mtu": 1420, "x": 1`), 1),
		bytes.Replace(valid, []byte(`"mtu": 1420`), []byte(`"mtu": 1, "mtu": 1420`), 1),
		valid[:len(valid)/2],
		[]byte("null"), []byte("{}"), []byte("[]"), []byte(""), []byte(`{"schema_version":1}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeConfig(b)
		if err != nil {
			if c != nil {
				t.Fatal("non-nil config with error")
			}
			return
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("decoded config does not validate: %v", err)
		}
		enc, err := EncodeConfig(c)
		if err != nil {
			t.Fatalf("decoded config cannot be encoded: %v", err)
		}
		c2, err := DecodeConfig(enc)
		if err != nil {
			t.Fatalf("re-encoded config is rejected: %v\n%s", err, enc)
		}
		enc2, err := EncodeConfig(c2)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(enc, enc2) {
			t.Fatalf("encoding is not stable:\n%s\nvs\n%s", enc, enc2)
		}
	})
}
