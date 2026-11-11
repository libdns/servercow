// Package servercow implements a libdns provider for the Servercow DNS API.
//
// The Servercow DNS API is documented at:
// https://wiki.servercow.de/en/domains/dns_api/api-syntax/
//
// Authentication uses a username and password created in the Servercow customer
// portal under "DNS API".
//
// Supported record types are A, AAAA, CNAME, TXT, MX, CAA, TLSA, SRV, SSHFP,
// SMIMEA, HTTPS and SVCB.
//
// The API stores multiple content values under one (name, type) key only for
// TXT, CAA, TLSA, HTTPS and SVCB. For all other types, including SRV, SSHFP and
// SMIMEA, only a single value is stored per (name, type) pair; SetRecords
// returns an error if more than one value is supplied for such a pair.
//
// Note on AppendRecords: For multi-value record types (TXT, CAA, TLSA, HTTPS,
// SVCB), this method performs a read-modify-write to preserve existing values.
// For single-value types it behaves identically to SetRecords because the
// Servercow API stores only one value set per (name, type) pair and does not
// distinguish between create and update.
//
// Servercow's current API restricts the owner names and content it accepts for
// some types: owner names containing "_" are rejected for SRV, SSHFP, SMIMEA
// and CAA, and SRV content is only accepted with the target "." (a real target
// name is rejected). Conventional SRV records such as _sip._tcp therefore
// cannot currently be created through the API.
package servercow

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider implements the libdns DNS provider interfaces for Servercow.
type Provider struct {
	// Username is the Servercow DNS API username.
	Username string `json:"username"`
	// Password is the Servercow DNS API password.
	Password string `json:"password"`

	once   sync.Once
	cached *client
}

// getClient returns the shared API client, initialising it once.
func (p *Provider) getClient() *client {
	p.once.Do(func() {
		p.cached = newClient(p.Username, p.Password)
	})
	return p.cached
}

// multiValueTypes lists the Servercow record types that accept multiple content
// values under a single (name, type) key. All other supported types (A, AAAA,
// CNAME, MX, SRV, SSHFP, SMIMEA) are single-value.
var multiValueTypes = map[string]bool{
	"TXT":   true,
	"CAA":   true,
	"TLSA":  true,
	"SVCB":  true,
	"HTTPS": true,
}

// GetRecords returns all DNS records for the given zone.
// zone must be a fully-qualified domain name with a trailing dot (e.g. "example.com.").
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	c := p.getClient()
	bareZone := strings.TrimSuffix(zone, ".")

	recs, err := c.getRecords(ctx, bareZone)
	if err != nil {
		return nil, fmt.Errorf("servercow: GetRecords %s: %w", zone, err)
	}

	var result []libdns.Record
	for _, r := range recs {
		result = append(result, toLibdnsRecords(r)...)
	}
	return result, nil
}

// AppendRecords adds records to the zone. For multi-value types (TXT, CAA,
// TLSA, SVCB, HTTPS) it reads existing values first and merges the new ones
// to avoid overwriting. For single-value types it behaves like SetRecords.
//
// When merging into an existing multi-value record, the TTL of the existing
// record is preserved (the caller-supplied TTL is ignored). This is intentional:
// the Servercow API stores one TTL per (name, type) pair, and changing it while
// appending a value would be a surprising side effect.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	c := p.getClient()
	bareZone := strings.TrimSuffix(zone, ".")

	existing, err := c.getRecords(ctx, bareZone)
	if err != nil {
		return nil, fmt.Errorf("servercow: AppendRecords get existing %s: %w", zone, err)
	}

	var appended []libdns.Record
	for _, rec := range recs {
		rr := rec.RR()
		name := toServercowName(rr.Name, zone)

		toPost := record{
			Name: name,
			Type: rr.Type,
			TTL:  int(rr.TTL.Seconds()),
		}

		if multiValueTypes[rr.Type] {
			// merge: keep existing values and add new one; preserve existing TTL
			existingRec := findRecord(existing, name, rr.Type)
			if existingRec != nil {
				toPost.Content = append(make(value, 0, len(existingRec.Content)), existingRec.Content...)
				toPost.TTL = existingRec.TTL
			}
			if !containsValue(toPost.Content, rr.Data) {
				toPost.Content = append(toPost.Content, rr.Data)
			}
		} else {
			toPost.Content = value{rr.Data}
		}

		if err := c.createUpdateRecord(ctx, bareZone, toPost); err != nil {
			return nil, fmt.Errorf("servercow: AppendRecords %s %s: %w", rr.Type, rr.Name, err)
		}
		appended = append(appended, rec)
	}
	return appended, nil
}

// SetRecords sets records in the zone, creating or replacing as needed.
// For a given (name, type) pair, any previous content is fully replaced.
//
// Only multi-value types may carry more than one value for the same (name,
// type) pair. For single-value types the Servercow API stores a single content
// value, so SetRecords returns an error if multiple values are supplied for one
// pair instead of letting the API fail with an opaque HTTP 500 response.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	c := p.getClient()
	bareZone := strings.TrimSuffix(zone, ".")

	// Group by (name, type) so multi-value types are posted as a single record.
	type key struct{ name, typ string }
	grouped := make(map[key][]libdns.Record)
	var order []key
	for _, rec := range recs {
		rr := rec.RR()
		k := key{toServercowName(rr.Name, zone), rr.Type}
		if _, exists := grouped[k]; !exists {
			order = append(order, k)
		}
		grouped[k] = append(grouped[k], rec)
	}

	// Reject multiple values for a single-value type before issuing any request:
	// the Servercow API stores only one content value per (name, type) pair for
	// these types and answers with HTTP 500 when it receives an array.
	for _, k := range order {
		if group := grouped[k]; !multiValueTypes[k.typ] && len(group) > 1 {
			return nil, fmt.Errorf("servercow: SetRecords %s %s: type supports only one value per name and type (got %d)", k.typ, toLibdnsName(k.name), len(group))
		}
	}

	var set []libdns.Record
	for _, k := range order {
		group := grouped[k]
		toPost := record{
			Name: k.name,
			Type: k.typ,
		}
		for i, rec := range group {
			rr := rec.RR()
			if i == 0 {
				toPost.TTL = int(rr.TTL.Seconds())
			}
			toPost.Content = append(toPost.Content, rr.Data)
		}

		if err := c.createUpdateRecord(ctx, bareZone, toPost); err != nil {
			return nil, fmt.Errorf("servercow: SetRecords %s %s: %w", k.typ, k.name, err)
		}
		set = append(set, group...)
	}
	return set, nil
}

// DeleteRecords removes records from the zone.
// For multi-value types (TXT, CAA, TLSA, SVCB, HTTPS) it reads existing values once and removes
// only the matching ones; if all values are removed it issues a full DELETE.
// For single-value types it issues a DELETE directly.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	c := p.getClient()
	bareZone := strings.TrimSuffix(zone, ".")

	// Pre-fetch all records once for multi-value read-modify-write operations,
	// consistent with AppendRecords. Avoids N GET requests for N multi-value deletes.
	existingRecords, err := c.getRecords(ctx, bareZone)
	if err != nil {
		return nil, fmt.Errorf("servercow: DeleteRecords get existing %s: %w", zone, err)
	}

	var deleted []libdns.Record
	for _, rec := range recs {
		rr := rec.RR()
		name := toServercowName(rr.Name, zone)

		if multiValueTypes[rr.Type] {
			// Read-modify-write: remove only the matching value.
			existingRec := findRecord(existingRecords, name, rr.Type)
			if existingRec == nil {
				// nothing to delete
				continue
			}

			remaining := removeValue(existingRec.Content, rr.Data)

			if len(remaining) == 0 {
				// delete the whole record
				if err := c.deleteRecord(ctx, bareZone, record{Name: name, Type: rr.Type}); err != nil {
					return nil, fmt.Errorf("servercow: DeleteRecords %s %s: %w", rr.Type, name, err)
				}
			} else {
				// update with remaining values
				toPost := record{
					Name:    existingRec.Name,
					Type:    existingRec.Type,
					TTL:     existingRec.TTL,
					Content: remaining,
				}
				if err := c.createUpdateRecord(ctx, bareZone, toPost); err != nil {
					return nil, fmt.Errorf("servercow: DeleteRecords update %s %s: %w", rr.Type, name, err)
				}
				// Update the in-memory view so subsequent deletes in this batch see the right state.
				existingRec.Content = remaining
			}
		} else {
			if err := c.deleteRecord(ctx, bareZone, record{Name: name, Type: rr.Type}); err != nil {
				return nil, fmt.Errorf("servercow: DeleteRecords %s %s: %w", rr.Type, name, err)
			}
		}
		deleted = append(deleted, rec)
	}
	return deleted, nil
}

// toServercowName converts a libdns record name to the Servercow API name format.
// libdns uses "@" for the zone apex; Servercow uses an empty string.
// libdns names are relative to the zone; Servercow names are also relative.
func toServercowName(name, zone string) string {
	if name == "@" || name == "" {
		return ""
	}
	// Strip trailing dot from zone for comparison purposes.
	bareZone := strings.TrimSuffix(zone, ".")
	// If name is somehow an absolute FQDN, make it relative.
	name = strings.TrimSuffix(name, "."+bareZone)
	name = strings.TrimSuffix(name, ".")
	return name
}

// toLibdnsName converts a Servercow API name to a libdns record name.
// Servercow uses "" for the zone apex; libdns uses "@".
func toLibdnsName(name string) string {
	if name == "" {
		return "@"
	}
	return name
}

// toLibdnsRecords converts a Servercow record to one or more libdns.Record values.
// Multi-value types (TXT, CAA, TLSA, SVCB, HTTPS) produce one libdns.Record per content value.
// Servercow record names are already zone-relative, so no zone stripping is needed.
func toLibdnsRecords(r record) []libdns.Record {
	name := toLibdnsName(r.Name)
	ttl := time.Duration(r.TTL) * time.Second

	var records []libdns.Record
	for _, content := range r.Content {
		records = append(records, libdns.RR{
			Name: name,
			Type: r.Type,
			TTL:  ttl,
			Data: content,
		})
	}
	return records
}

// findRecord searches a slice of records for one matching name and type.
func findRecord(records []record, name, typ string) *record {
	for i := range records {
		if records[i].Name == name && records[i].Type == typ {
			return &records[i]
		}
	}
	return nil
}

// containsValue reports whether s is in v.
func containsValue(v value, s string) bool {
	for _, item := range v {
		if item == s {
			return true
		}
	}
	return false
}

// removeValue returns a new value slice with all occurrences of s removed.
func removeValue(v value, s string) value {
	var result value
	for _, item := range v {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}

// Interface guards — compile-time checks that Provider implements the libdns interfaces.
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
