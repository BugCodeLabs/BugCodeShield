package settings

import "testing"

func TestHint(t *testing.T) {
	if got := Hint(""); got != "" {
		t.Fatalf("empty secret hint = %q", got)
	}
	if got := Hint("abcd"); got != "••••" {
		t.Fatalf("short secret hint = %q", got)
	}
	if got := Hint("sk-abcdefghijklmnopqrstuvwxyz"); got != "••••wxyz" {
		t.Fatalf("hint = %q", got)
	}
}
