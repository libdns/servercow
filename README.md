# libdns/servercow

[![Go Reference](https://pkg.go.dev/badge/github.com/libdns/servercow.svg)](https://pkg.go.dev/github.com/libdns/servercow)

This package implements the [libdns](https://github.com/libdns/libdns) interfaces for [Servercow](https://servercow.de), allowing DNS records to be managed via the Servercow DNS API.

## Authentication

The Servercow DNS API uses username/password authentication passed in request headers. See [Servercow docs](https://wiki.servercow.de/de/domains/dns_api/api-syntax/) for more info.

## Usage

```go
import "github.com/libdns/servercow"

provider := servercow.Provider{
    Username: "your-username",
    Password: "your-password",
}
```

## Supported record types

A, AAAA, CNAME, TXT, MX, CAA, TLSA, SRV, SSHFP, SMIMEA, HTTPS, SVCB

## Notes

- `AppendRecords` for multi-value types (TXT, CAA, TLSA, HTTPS, SVCB) performs a read-modify-write to preserve existing values. For single-value types, it behaves like `SetRecords` because the Servercow API stores only one value set per (name, type) pair.
- All other types, including SRV, SSHFP and SMIMEA, are single-value: the Servercow API stores only one content value per (name, type) pair. `SetRecords` returns an error when more than one value is supplied for such a pair instead of letting the API reject the request.
- The Servercow API currently restricts the owner names and content it accepts for some types: owner names containing `_` are rejected for SRV, SSHFP, SMIMEA and CAA, and SRV content is only accepted with the target `.` (a real target name is rejected). Conventional SRV records such as `_sip._tcp` therefore cannot currently be created through the API.
- Zone listing is not supported (no API endpoint).
