package servercow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
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

func TestAppendRecords_RejectsMultipleValuesForSingleValueType(t *testing.T) {
	p := &Provider{Username: "dummy", Password: "dummy"}
	recs := []libdns.Record{
		libdns.RR{Name: "host", Type: "SSHFP", TTL: 120 * time.Second, Data: "value-1"},
		libdns.RR{Name: "host", Type: "SSHFP", TTL: 120 * time.Second, Data: "value-2"},
	}
	// As with SetRecords, the check runs before the initial GET.
	_, err := p.AppendRecords(context.Background(), "example.com.", recs)
	if err == nil || !strings.Contains(err.Error(), "AppendRecords SSHFP host: type supports only one value") {
		t.Fatalf("expected AppendRecords duplicate error, got %v", err)
	}
}

func TestCheckSingleValueDuplicates(t *testing.T) {
	rr := func(name, typ, data string) libdns.Record {
		return libdns.RR{Name: name, Type: typ, Data: data}
	}
	tests := []struct {
		name    string
		recs    []libdns.Record
		wantErr bool
	}{
		{"multi-value type", []libdns.Record{rr("host", "TXT", "a"), rr("host", "TXT", "b")}, false},
		{"multi-value type lower-case", []libdns.Record{rr("host", "txt", "a"), rr("HOST", "txt", "b")}, false},
		{"single-value duplicate", []libdns.Record{rr("host", "SSHFP", "a"), rr("host", "SSHFP", "b")}, true},
		{"single-value duplicate mixed case", []libdns.Record{rr("host", "sshfp", "a"), rr("HOST", "SSHFP", "b")}, true},
		{"single-value different names", []libdns.Record{rr("host", "SSHFP", "a"), rr("other", "SSHFP", "b")}, false},
		{"single-value different types", []libdns.Record{rr("host", "SSHFP", "a"), rr("host", "SMIMEA", "b")}, false},
		{"apex spellings", []libdns.Record{rr("@", "MX", "a"), rr("", "MX", "b")}, true},
		{"absolute apex and @", []libdns.Record{rr("example.com.", "MX", "a"), rr("@", "MX", "b")}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSingleValueDuplicates("SetRecords", "example.com.", tc.recs)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestToServercowName_AbsoluteFQDN(t *testing.T) {
	tests := []struct {
		name, zone, want string
	}{
		{"host.example.com.", "example.com.", "host"},
		{"host.sub.example.com.", "example.com.", "host.sub"},
		{"example.com.", "example.com.", ""},
		{"example.com.", "example.com", ""},
		{"host", "example.com.", "host"},
	}
	for _, tc := range tests {
		if got := toServercowName(tc.name, tc.zone); got != tc.want {
			t.Errorf("toServercowName(%q, %q) = %q, want %q", tc.name, tc.zone, got, tc.want)
		}
	}
}

func TestFindRecord_CaseInsensitive(t *testing.T) {
	recs := []record{{Name: "Host", Type: "TXT", Content: value{"a"}}}
	if findRecord(recs, "host", "txt") == nil {
		t.Error("expected case-insensitive match")
	}
	if findRecord(recs, "other", "TXT") != nil {
		t.Error("unexpected match for different name")
	}
}

// --- Fake API tests ---

// fakeServer implements the subset of the Servercow API used by the provider,
// storing one record per (name, type) pair like the real API does.
type fakeServer struct {
	mu      sync.Mutex
	records []record
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(f.records)
	case http.MethodPost:
		var rec record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		replaced := false
		for i := range f.records {
			if strings.EqualFold(f.records[i].Name, rec.Name) && strings.EqualFold(f.records[i].Type, rec.Type) {
				f.records[i] = rec
				replaced = true
				break
			}
		}
		if !replaced {
			f.records = append(f.records, rec)
		}
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	case http.MethodDelete:
		var rec record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		kept := f.records[:0]
		for _, existing := range f.records {
			if strings.EqualFold(existing.Name, rec.Name) && strings.EqualFold(existing.Type, rec.Type) {
				continue
			}
			kept = append(kept, existing)
		}
		f.records = kept
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (f *fakeServer) snapshot() []record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]record(nil), f.records...)
}

func newFakeProvider(t *testing.T, records ...record) (*Provider, *fakeServer) {
	t.Helper()
	f := &fakeServer{records: records}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &Provider{baseURL: u}, f
}

func TestAppendRecords_MergesValuesWithinBatch(t *testing.T) {
	p, f := newFakeProvider(t, record{
		Name: "host", Type: "TXT", TTL: 120, Content: value{"old"},
	})
	recs := []libdns.Record{
		libdns.RR{Name: "host", Type: "TXT", TTL: 300 * time.Second, Data: "a"},
		libdns.RR{Name: "host", Type: "TXT", TTL: 300 * time.Second, Data: "b"},
	}
	if _, err := p.AppendRecords(context.Background(), "example.com.", recs); err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	got := f.snapshot()
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(got), got)
	}
	if want := []string{"old", "a", "b"}; strings.Join(got[0].Content, ",") != strings.Join(want, ",") {
		t.Errorf("content = %v, want %v", got[0].Content, want)
	}
	if got[0].TTL != 120 {
		t.Errorf("TTL = %d, want existing TTL 120", got[0].TTL)
	}
}

func TestSetRecords_LowercaseMultiValueGrouped(t *testing.T) {
	p, f := newFakeProvider(t)
	recs := []libdns.Record{
		libdns.RR{Name: "host", Type: "txt", TTL: 120 * time.Second, Data: "a"},
		libdns.RR{Name: "host", Type: "txt", TTL: 120 * time.Second, Data: "b"},
	}
	if _, err := p.SetRecords(context.Background(), "example.com.", recs); err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	got := f.snapshot()
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(got), got)
	}
	if got[0].Type != "TXT" {
		t.Errorf("type = %q, want TXT", got[0].Type)
	}
	if len(got[0].Content) != 2 {
		t.Errorf("content = %v, want two values", got[0].Content)
	}
}

func TestSetRecords_MixedBatch(t *testing.T) {
	p, f := newFakeProvider(t)
	recs := []libdns.Record{
		libdns.RR{Name: "host", Type: "TXT", TTL: 120 * time.Second, Data: "a"},
		libdns.RR{Name: "host", Type: "TXT", TTL: 120 * time.Second, Data: "b"},
		libdns.RR{Name: "host", Type: "SSHFP", TTL: 120 * time.Second, Data: "2 1 abcdef"},
	}
	if _, err := p.SetRecords(context.Background(), "example.com.", recs); err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	got := f.snapshot()
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(got), got)
	}
}

func TestAppendRecords_MixedBatchRejectedAtomically(t *testing.T) {
	p, f := newFakeProvider(t)
	recs := []libdns.Record{
		libdns.RR{Name: "host", Type: "TXT", TTL: 120 * time.Second, Data: "a"},
		libdns.RR{Name: "host", Type: "SSHFP", TTL: 120 * time.Second, Data: "one"},
		libdns.RR{Name: "host", Type: "SSHFP", TTL: 120 * time.Second, Data: "two"},
	}
	_, err := p.AppendRecords(context.Background(), "example.com.", recs)
	if err == nil || !strings.Contains(err.Error(), "supports only one value per name and type") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
	if got := f.snapshot(); len(got) != 0 {
		t.Fatalf("no request should have been made, got records %+v", got)
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
