package project

import (
	"path/filepath"
	"testing"
)

func TestConfirmProjectName(t *testing.T) {
	if !ConfirmProjectName("Shop API", "Shop API") {
		t.Fatal("exact name should match")
	}
	if ConfirmProjectName("shop api", "Shop API") {
		t.Fatal("case mismatch must not confirm")
	}
	if !ConfirmProjectName("  Shop API  ", "Shop API") {
		t.Fatal("typed name is trimmed")
	}
	if ConfirmProjectName("", "Shop API") {
		t.Fatal("empty name must not confirm")
	}
	if ConfirmProjectName("Shop", "Shop API") {
		t.Fatal("partial name must not confirm")
	}
}

func TestStoredSourceDirOnlyUnderHostSources(t *testing.T) {
	s := &Service{sourcesDir: "/var/lib/bugcodeshield/sources", hostSources: "/home/me/proj/data/sources"}
	got := s.storedSourceDir(ptr("/home/me/proj/data/sources/abc/src"))
	want := filepath.Join("/var/lib/bugcodeshield/sources", "abc")
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if s.storedSourceDir(ptr("/home/me/code/my-app")) != "" {
		t.Fatal("must not delete the user's own folder")
	}
}

func ptr(v string) *string { return &v }
