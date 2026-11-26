package scan

import "testing"

func TestAllowedWSOrigin(t *testing.T) {
	cases := []struct {
		origin string
		ok     bool
	}{
		{"", true},
		{"http://localhost:3000", true},
		{"http://127.0.0.1:3000", true},
		{"https://localhost", true},
		{"http://evil.example", false},
		{"http://localhost.evil.com", false},
		{"://bad", false},
	}
	for _, tc := range cases {
		if got := allowedWSOrigin(tc.origin); got != tc.ok {
			t.Errorf("allowedWSOrigin(%q)=%v want %v", tc.origin, got, tc.ok)
		}
	}
}
