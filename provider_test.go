package servercow

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
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

func TestMultiValueTypes(t *testing.T) {
	// exactly the types that accept a JSON array of content values
	for _, typ := range []string{"TXT", "CAA", "TLSA", "HTTPS", "SVCB"} {
		if !multiValueTypes[typ] {
			t.Errorf("multiValueTypes[%q] = false, want true", typ)
		}
	}
	// all other supported types are single-value
	for _, typ := range []string{"A", "AAAA", "CNAME", "MX", "SRV", "SSHFP", "SMIMEA"} {
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

func TestToLibdnsRecords_NewSingleValueTypes(t *testing.T) {
	cases := []record{
		{Name: "host", Type: "SSHFP", TTL: 120, Content: value{"2 1 abcdef"}},
		{Name: "host", Type: "SMIMEA", TTL: 120, Content: value{"3 1 1 abcdef"}},
		{Name: "", Type: "SRV", TTL: 120, Content: value{"0 0 0 ."}},
	}
	for _, r := range cases {
		recs := toLibdnsRecords(r)
		if len(recs) != 1 {
			t.Fatalf("%s: got %d records, want 1", r.Type, len(recs))
		}
		rr := recs[0].RR()
		if rr.Type != r.Type || rr.TTL != time.Duration(r.TTL)*time.Second || rr.Data != r.Content[0] {
			t.Errorf("%s: got %+v, want type=%s ttl=%ds data=%q", r.Type, rr, r.Type, r.TTL, r.Content[0])
		}
		if want := toLibdnsName(r.Name); rr.Name != want {
			t.Errorf("%s: got name %q, want %q", r.Type, rr.Name, want)
		}
	}
}

func TestSetRecords_RejectsMultipleValuesForSingleValueType(t *testing.T) {
	p := &Provider{Username: "dummy", Password: "dummy"}
	for _, typ := range []string{"A", "AAAA", "CNAME", "MX", "SRV", "SSHFP", "SMIMEA"} {
		t.Run(typ, func(t *testing.T) {
			recs := []libdns.Record{
				libdns.RR{Name: "host", Type: typ, TTL: 120 * time.Second, Data: "value-1"},
				libdns.RR{Name: "host", Type: typ, TTL: 120 * time.Second, Data: "value-2"},
			}
			// The check must run before any API request, so no network access
			// (and no valid credentials) is needed here.
			_, err := p.SetRecords(context.Background(), "example.com.", recs)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), "supports only one value per name and type") {
				t.Errorf("unexpected error: %v", err)
			}
			if !strings.Contains(err.Error(), typ) {
				t.Errorf("error does not mention record type %s: %v", typ, err)
			}
		})
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
