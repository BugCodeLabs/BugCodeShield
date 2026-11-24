package source

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeExtractRejectsZipSlip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("../evil.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("nope"))
	_ = zw.Close()

	dest := t.TempDir()
	_, err = SafeExtractZip(bytes.NewReader(buf.Bytes()), int64(buf.Len()), dest)
	if err == nil {
		t.Fatal("expected zip slip archive to be rejected")
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dest), "evil.txt")); statErr == nil {
		t.Fatal("zip slip wrote outside destination")
	}
}

func TestSafeExtractKeepsRelativeFiles(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("app/main.js")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("console.log(1)"))
	_ = zw.Close()

	dest := t.TempDir()
	count, err := SafeExtractZip(bytes.NewReader(buf.Bytes()), int64(buf.Len()), dest)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count=%d", count)
	}
	raw, err := os.ReadFile(filepath.Join(dest, "app", "main.js"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "console.log(1)" {
		t.Fatalf("content=%q", raw)
	}
}
