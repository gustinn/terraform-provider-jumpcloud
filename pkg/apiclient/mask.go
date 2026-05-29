package apiclient

import (
	"encoding/json"
	"strings"
)

// sensitiveKeys is the set of JSON field names (compared case-insensitively)
// whose values must be masked before being written to any log. Keep this list
// lowercase; lookups are performed with strings.ToLower.
var sensitiveKeys = map[string]bool{
	"api_key":       true,
	"apikey":        true,
	"password":      true,
	"passwd":        true,
	"secret":        true,
	"client_secret": true,
	"clientsecret":  true,
	"token":         true,
	"access_token":  true,
	"accesstoken":   true,
	"refresh_token": true,
	"refreshtoken":  true,
	"private_key":   true,
	"privatekey":    true,
	"connect_key":   true,
	"connectkey":    true,
	"shared_secret": true,
	"sharedsecret":  true,
	"key":           true,
}

// maskValue masks a secret string, keeping the first 3 and last 3 characters
// visible so logs remain useful for correlation without exposing the secret.
// Values short enough that revealing 6 characters would expose most of the
// secret are masked entirely.
func maskValue(s string) string {
	const visible = 3
	if len(s) <= visible*2 {
		return strings.Repeat("*", len(s))
	}
	return s[:visible] + strings.Repeat("*", len(s)-visible*2) + s[len(s)-visible:]
}

// MaskSensitive returns a loggable representation of a request or response
// body with the values of known sensitive fields masked (see maskValue).
//
// If the body is valid JSON it is walked recursively and only sensitive field
// values are masked, preserving the rest of the structure for debugging. If
// the body is not JSON we cannot tell which parts are sensitive, so the entire
// payload is masked to avoid accidentally leaking a secret.
func MaskSensitive(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		// Not introspectable JSON; mask the whole thing to be safe.
		return maskValue(string(body))
	}

	masked := maskNode(data)
	out, err := json.Marshal(masked)
	if err != nil {
		return maskValue(string(body))
	}
	return string(out)
}

// maskNode recursively walks a decoded JSON value, masking the values of any
// fields whose names appear in sensitiveKeys.
func maskNode(node any) any {
	switch v := node.(type) {
	case map[string]any:
		for key, val := range v {
			if s, ok := val.(string); ok && sensitiveKeys[strings.ToLower(key)] {
				v[key] = maskValue(s)
				continue
			}
			v[key] = maskNode(val)
		}
		return v
	case []any:
		for i, item := range v {
			v[i] = maskNode(item)
		}
		return v
	default:
		return node
	}
}
