package servercow

import "encoding/json"

// record mirrors the Servercow API DNS record structure.
type record struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl,omitempty"`
	Content value  `json:"content,omitempty"`
}

// value represents a DNS record's content. The Servercow API accepts either a
// plain JSON string (for single-value records) or a JSON array (for multi-value
// record types such as TXT, CAA, TLSA). This type handles both forms.
type value []string

func (v value) MarshalJSON() ([]byte, error) {
	if len(v) == 0 {
		return nil, nil
	}
	if len(v) == 1 {
		return json.Marshal(v[0])
	}
	return json.Marshal([]string(v))
}

func (v *value) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '[' {
		return json.Unmarshal(b, (*[]string)(v))
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*v = value{s}
	return nil
}

// message is the JSON body returned by the Servercow API for POST and DELETE
// operations. Note: the API returns HTTP 200 even for errors; callers must
// inspect ErrorMsg.
type message struct {
	Message  string `json:"message,omitempty"`
	ErrorMsg string `json:"error,omitempty"`
}

func (m message) Error() string { return m.ErrorMsg }
