# libdns/servercow

This package implements the [libdns](https://github.com/libdns/libdns) interfaces for [Servercow](https://servercow.de), allowing DNS records to be managed via the Servercow DNS API.

## Authentication

The Servercow DNS API uses username/password authentication passed in request headers. Create a DNS API user in the [Servercow customer portal](https://www.servercow.de/dns-api).

## Usage

import "github.com/libdns/servercow"

provider := servercow.Provider{
    Username: "your-username",
    Password: "your-password",
}

## Supported record types

TXT, A, AAAA, CNAME, MX, CAA, TLSA

## Notes

- `AppendRecords` for multi-value types (TXT, CAA, TLSA) performs a read-modify-write to preserve existing values. For single-value types (A, AAAA, CNAME, MX), it behaves like `SetRecords` because the Servercow API stores only one value set per (name, type) pair.
- Zone listing is not supported (no API endpoint).
