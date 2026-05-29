package apiclient

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMaskValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"short fully masked", "abc", "***"},
		{"exactly six fully masked", "abcdef", "******"},
		{"seven keeps ends", "abcdefg", "abc*efg"},
		{"long keeps three each end", "supersecretvalue", "sup**********lue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskValue(tt.in); got != tt.want {
				t.Errorf("maskValue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMaskSensitive_MasksKnownFields(t *testing.T) {
	body := []byte(`{"name":"prod-key","api_key":"abcdef1234567890","nested":{"password":"hunter2hunter2"},"list":[{"token":"tok_aaaaaaaaaa"}]}`)

	out := MaskSensitive(body)

	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("masked output is not valid JSON: %v\noutput: %s", err, out)
	}

	// Non-sensitive field is preserved.
	if decoded["name"] != "prod-key" {
		t.Errorf("non-sensitive field altered: got %v", decoded["name"])
	}

	// The raw secrets must not appear anywhere in the output.
	for _, secret := range []string{"abcdef1234567890", "hunter2hunter2", "tok_aaaaaaaaaa"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q leaked in masked output: %s", secret, out)
		}
	}

	// First/last 3 chars of the api_key remain for correlation.
	if got := decoded["api_key"].(string); got != "abc**********890" {
		t.Errorf("api_key mask = %q, want %q", got, "abc**********890")
	}
}

func TestMaskSensitive_NonJSONFullyMasked(t *testing.T) {
	body := []byte("plaintextsecretvalue")
	out := MaskSensitive(body)
	if strings.Contains(out, "secret") || out == string(body) {
		t.Errorf("non-JSON body was not masked: %q", out)
	}
}

func TestMaskSensitive_Empty(t *testing.T) {
	if got := MaskSensitive(nil); got != "" {
		t.Errorf("MaskSensitive(nil) = %q, want empty", got)
	}
}
