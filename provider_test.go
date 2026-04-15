package servercow

import (
	"os"
	"testing"
)

// --- Name mapping unit tests ---

func TestToServercowName_Apex(t *testing.T) {
	got := toServercowName("@", "example.com.")
	if got != "" {
		t.Errorf("toServercowName(@) = %q, want empty string", got)
	}
}

func TestToServercowName_EmptyIsApex(t *testing.T) {
	got := toServercowName("", "example.com.")
	if got != "" {
		t.Errorf("toServercowName('') = %q, want empty string", got)
	}
}

func TestToServercowName_Sub(t *testing.T) {
	got := toServercowName("_acme-challenge", "example.com.")
	if got != "_acme-challenge" {
		t.Errorf("toServercowName(_acme-challenge) = %q, want _acme-challenge", got)
	}
}

func TestToServercowName_Nested(t *testing.T) {
	got := toServercowName("_acme-challenge.www", "example.com.")
	if got != "_acme-challenge.www" {
		t.Errorf("got %q, want _acme-challenge.www", got)
	}
}

func TestToLibdnsName_Empty(t *testing.T) {
	got := toLibdnsName("")
	if got != "@" {
		t.Errorf("toLibdnsName('') = %q, want @", got)
	}
}

func TestToLibdnsName_Sub(t *testing.T) {
	got := toLibdnsName("sub")
	if got != "sub" {
		t.Errorf("toLibdnsName(sub) = %q, want sub", got)
	}
}

func TestContainsValue(t *testing.T) {
	v := value{"a", "b", "c"}
	if !containsValue(v, "b") {
		t.Error("expected containsValue to find 'b'")
	}
	if containsValue(v, "z") {
		t.Error("expected containsValue to not find 'z'")
	}
}

func TestRemoveValue(t *testing.T) {
	v := value{"a", "b", "c"}
	result := removeValue(v, "b")
	if len(result) != 2 || result[0] != "a" || result[1] != "c" {
		t.Errorf("removeValue result = %v, want [a c]", result)
	}
}

func TestRemoveValue_NotPresent(t *testing.T) {
	v := value{"a", "b"}
	result := removeValue(v, "z")
	if len(result) != 2 {
		t.Errorf("removeValue (not present) changed slice: %v", result)
	}
}

// --- Integration tests (require live credentials) ---

func TestIntegration_GetRecords(t *testing.T) {
	username := os.Getenv("SERVERCOW_USERNAME")
	password := os.Getenv("SERVERCOW_PASSWORD")
	zone := os.Getenv("SERVERCOW_TEST_ZONE") // e.g. "example.com."
	if username == "" || password == "" || zone == "" {
		t.Skip("SERVERCOW_USERNAME, SERVERCOW_PASSWORD, SERVERCOW_TEST_ZONE not set; skipping integration test")
	}

	p := &Provider{Username: username, Password: password}
	recs, err := p.GetRecords(t.Context(), zone)
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	t.Logf("GetRecords returned %d records", len(recs))
	for _, r := range recs {
		rr := r.RR()
		t.Logf("  %s %s %s", rr.Type, rr.Name, rr.Data)
	}
}
