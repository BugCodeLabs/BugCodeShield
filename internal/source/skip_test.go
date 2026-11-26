package source

import (
	"os"
	"path/filepath"
	"testing"
)

func TestShouldSkipPathGeneratedDirs(t *testing.T) {
	skip := []string{
		"node_modules/left-pad/index.js",
		"apps/web/node_modules/react/index.js",
		".git/config",
		"dist/main.js",
		"coverage/lcov.info",
		".next/cache/index",
		".nx/cache/foo",
		"apps/api/.turbo/turbo-foo.log",
		".cache/yarn",
		"packages/ui/.cache/ts",
		"venv/lib/python3.12/site.py",
		".venv/bin/python",
		"app/__pycache__/main.cpython-312.pyc",
		"services/api/vendor/github.com/foo/bar.go",
		"backend/target/classes/App.class",
		"cli/bin/Debug/net8.0/app.dll",
		"mobile/obj/project.assets.json",
		"crate/target/debug/lib.rlib",
		"mix/_build/dev/lib/app",
		"ios/Pods/Alamofire/Alamofire.swift",
		"infra/.terraform/providers/lock.json",
	}
	for _, path := range skip {
		if !ShouldSkipPath(path) {
			t.Errorf("expected skip %q", path)
		}
	}
	keep := []string{
		"src/app.ts",
		"apps/web/src/page.tsx",
		"package.json",
		"cmd/api/main.go",
		"packages/api/src/main.go",
		"internal/scan/service.go",
		"app/models/user.py",
		"src/main/java/com/example/App.java",
		"lib/tasks/import.rb",
	}
	for _, path := range keep {
		if ShouldSkipPath(path) {
			t.Errorf("did not expect skip %q", path)
		}
	}
}

func TestFindSkipDirRelPathsNested(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "apps", "web", "node_modules", "x"))
	mustMkdir(t, filepath.Join(root, ".nx", "cache"))
	mustMkdir(t, filepath.Join(root, ".turbo"))
	mustMkdir(t, filepath.Join(root, ".cache"))
	mustMkdir(t, filepath.Join(root, "venv", "lib"))
	mustMkdir(t, filepath.Join(root, "target", "classes"))
	mustMkdir(t, filepath.Join(root, "src"))
	_ = os.WriteFile(filepath.Join(root, "src", "main.ts"), []byte("ok"), 0o644)

	found := map[string]bool{}
	for _, rel := range FindSkipDirRelPaths(root) {
		found[rel] = true
	}
	for _, want := range []string{"apps/web/node_modules", ".nx", ".turbo", ".cache", "venv", "target"} {
		if !found[want] {
			t.Errorf("missing skip dir %q in %v", want, found)
		}
	}
	if found["src"] {
		t.Fatal("src should not be skipped")
	}
}

func TestCountScanFilesSkipsGeneratedDirs(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "app.js"), []byte("ok"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "main.py"), []byte("ok"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "main.go"), []byte("ok"), 0o644)
	for _, dir := range []string{
		"node_modules/x",
		".git",
		"dist",
		"coverage",
		".next",
		".nx/cache",
		".turbo",
		".cache",
		"venv/lib",
		"__pycache__",
		"vendor/github.com/x",
		"target/classes",
		"bin/Debug",
	} {
		mustMkdir(t, filepath.Join(root, filepath.FromSlash(dir)))
		_ = os.WriteFile(filepath.Join(root, filepath.FromSlash(dir), "junk.js"), []byte("skip"), 0o644)
	}
	n, _, err := CountScanFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("counted %d, want 3", n)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}
