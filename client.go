package servercow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const baseAPIURL = "https://api.servercow.de/dns/v1/domains"

// client is an HTTP client for the Servercow DNS API.
type client struct {
	username   string
	password   string
	baseURL    *url.URL
	httpClient *http.Client
}

// newClient creates a new Servercow API client.
func newClient(username, password string) *client {
	base, _ := url.Parse(baseAPIURL)
	return &client{
		username:   username,
		password:   password,
		baseURL:    base,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// getRecords fetches all DNS records for the given zone (bare domain, no trailing dot).
func (c *client) getRecords(ctx context.Context, zone string) ([]record, error) {
	endpoint := c.baseURL.JoinPath(zone)
	req, err := newJSONRequest(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("servercow: build request: %w", err)
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("servercow: GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("servercow: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("servercow: read response: %w", err)
	}

	var records []record
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("servercow: decode records: %w (body: %s)", err, body)
	}
	return records, nil
}

// createUpdateRecord creates or fully replaces the DNS record for a given
// (name, type) pair. If a record with the same name and type already exists,
// the Servercow API replaces it entirely.
func (c *client) createUpdateRecord(ctx context.Context, zone string, r record) error {
	endpoint := c.baseURL.JoinPath(zone)
	req, err := newJSONRequest(ctx, http.MethodPost, endpoint.String(), r)
	if err != nil {
		return fmt.Errorf("servercow: build request: %w", err)
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("servercow: POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("servercow: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("servercow: read response: %w", err)
	}

	var msg message
	if err := json.Unmarshal(body, &msg); err != nil {
		// non-JSON response on success is fine
		return nil
	}
	if msg.ErrorMsg != "" {
		return fmt.Errorf("servercow: API error: %s", msg.ErrorMsg)
	}
	return nil
}

// deleteRecord removes the DNS record for a given (name, type) pair.
func (c *client) deleteRecord(ctx context.Context, zone string, r record) error {
	endpoint := c.baseURL.JoinPath(zone)
	// Only name and type are required for DELETE
	payload := struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}{Name: r.Name, Type: r.Type}
	req, err := newJSONRequest(ctx, http.MethodDelete, endpoint.String(), payload)
	if err != nil {
		return fmt.Errorf("servercow: build request: %w", err)
	}
	c.setAuth(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("servercow: DELETE %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("servercow: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("servercow: read response: %w", err)
	}

	var msg message
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil
	}
	if msg.ErrorMsg != "" {
		return fmt.Errorf("servercow: API error: %s", msg.ErrorMsg)
	}
	return nil
}

// setAuth adds the Servercow authentication headers to the request.
func (c *client) setAuth(req *http.Request) {
	req.Header.Set("X-Auth-Username", c.username)
	req.Header.Set("X-Auth-Password", c.password)
}

// newJSONRequest creates an HTTP request with JSON content type.
// payload may be nil for GET requests.
func newJSONRequest(ctx context.Context, method, endpoint string, payload any) (*http.Request, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}
