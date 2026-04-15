package servercow

import (
	"encoding/json"
	"testing"
)

func TestValueMarshalSingle(t *testing.T) {
	v := value{"hello"}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	// single value must marshal as a plain JSON string, not an array
	if string(b) != `"hello"` {
		t.Errorf("got %s, want %q", b, "hello")
	}
}

func TestValueMarshalMultiple(t *testing.T) {
	v := value{"a", "b"}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `["a","b"]` {
		t.Errorf("got %s, want [\"a\",\"b\"]", b)
	}
}

func TestValueMarshalEmpty(t *testing.T) {
	var v value
	b, err := json.Marshal(record{Name: "x", Type: "TXT", Content: v})
	if err != nil {
		t.Fatal(err)
	}
	// empty content must be omitted from JSON (omitempty)
	var r record
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Content) != 0 {
		t.Errorf("expected empty content, got %v", r.Content)
	}
}

func TestValueUnmarshalString(t *testing.T) {
	var v value
	if err := json.Unmarshal([]byte(`"hello"`), &v); err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || v[0] != "hello" {
		t.Errorf("got %v, want [hello]", v)
	}
}

func TestValueUnmarshalArray(t *testing.T) {
	var v value
	if err := json.Unmarshal([]byte(`["a","b","c"]`), &v); err != nil {
		t.Fatal(err)
	}
	if len(v) != 3 || v[0] != "a" || v[1] != "b" || v[2] != "c" {
		t.Errorf("got %v, want [a b c]", v)
	}
}

func TestRecordRoundtrip(t *testing.T) {
	original := record{
		Name:    "_acme-challenge",
		Type:    "TXT",
		TTL:     120,
		Content: value{"token1", "token2"},
	}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded record
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Name != original.Name || decoded.Type != original.Type || decoded.TTL != original.TTL {
		t.Errorf("record fields mismatch: got %+v, want %+v", decoded, original)
	}
	if len(decoded.Content) != 2 || decoded.Content[0] != "token1" || decoded.Content[1] != "token2" {
		t.Errorf("content mismatch: got %v, want [token1 token2]", decoded.Content)
	}
}
