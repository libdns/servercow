package servercow

import (
	"context"
	"os"
	"testing"
	"time"
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

func TestMultiValueTypes_ContainsHTTPSAndSVCB(t *testing.T) {
	for _, typ := range []string{"HTTPS", "SVCB"} {
		if !multiValueTypes[typ] {
			t.Errorf("multiValueTypes[%q] = false, want true", typ)
		}
	}
	// existing multi-value types must remain
	for _, typ := range []string{"TXT", "CAA", "TLSA"} {
		if !multiValueTypes[typ] {
			t.Errorf("multiValueTypes[%q] = false, want true", typ)
		}
	}
	// single-value types must remain absent
	for _, typ := range []string{"A", "AAAA", "CNAME", "MX"} {
		if multiValueTypes[typ] {
			t.Errorf("multiValueTypes[%q] = true, want false", typ)
		}
	}
}

func TestToLibdnsRecords_HTTPSMultiValue(t *testing.T) {
	r := record{
		Name:    "_https-probe",
		Type:    "HTTPS",
		TTL:     300,
		Content: value{"1 .", "2 . alpn=h3"},
	}
	recs := toLibdnsRecords(r)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	wantData := []string{"1 .", "2 . alpn=h3"}
	for i, rec := range recs {
		rr := rec.RR()
		if rr.Name != "_https-probe" || rr.Type != "HTTPS" || rr.TTL != 300*time.Second || rr.Data != wantData[i] {
			t.Errorf("record %d = %+v, want name=_https-probe type=HTTPS ttl=300s data=%q", i, rr, wantData[i])
		}
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
	recs, err := p.GetRecords(context.Background(), zone)
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	t.Logf("GetRecords returned %d records", len(recs))
	for _, r := range recs {
		rr := r.RR()
		t.Logf("  %s %s %s", rr.Type, rr.Name, rr.Data)
	}
}
