package source

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// SkipDirNames are generated, VCS, and dependency trees that scanners must not
// read. This is not Node-only: it covers every language this product scans
// (JS/TS, Python, Go, Java/Kotlin, PHP, Ruby, Rust, .NET, Dart, Elixir, Swift).
var SkipDirNames = []string{
	".git",
	".idea",
	".vscode",
	"__MACOSX",
	".cache",
	"tmp",
	".tmp",
	"dist",
	"build",
	"out",
	"coverage",
	"htmlcov",
	"node_modules",
	".pnpm-store",
	".yarn",
	"bower_components",
	".next",
	".nuxt",
	".output",
	".svelte-kit",
	".nx",
	".turbo",
	".parcel-cache",
	".vite",
	"__pycache__",
	".venv",
	"venv",
	"virtualenv",
	".tox",
	".nox",
	".mypy_cache",
	".pytest_cache",
	".ruff_cache",
	".eggs",
	".hypothesis",
	"vendor",
	".bundle",
	"target",
	".gradle",
	".build",
	"DerivedData",
	"Pods",
	"_build",
	"deps",
	"bin",
	"obj",
	".dart_tool",
	".terraform",
}

const maxSkipMounts = 200

var skipDirSet = func() map[string]struct{} {
	out := make(map[string]struct{}, len(SkipDirNames))
	for _, name := range SkipDirNames {
		out[strings.ToLower(name)] = struct{}{}
	}
	return out
}()

func IsSkipDirName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), "/")
	_, ok := skipDirSet[name]
	return ok
}

func ShouldSkipPath(rel string) bool {
	n := strings.ToLower(strings.TrimPrefix(filepath.ToSlash(rel), "./"))
	n = strings.Trim(n, "/")
	if n == "" || n == "." {
		return false
	}
	for _, part := range strings.Split(n, "/") {
		if _, ok := skipDirSet[part]; ok {
			return true
		}
	}
	return false
}

func shouldSkip(name string) bool {
	return ShouldSkipPath(name)
}

func SkipGlobs() []string {
	out := make([]string, 0, len(SkipDirNames))
	for _, name := range SkipDirNames {
		out = append(out, "**/"+name+"/**")
	}
	return out
}

func FindSkipDirRelPaths(root string) []string {
	var dirs []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if path == root {
			return nil
		}
		if !IsSkipDirName(d.Name()) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return filepath.SkipDir
		}
		dirs = append(dirs, filepath.ToSlash(rel))
		if len(dirs) >= maxSkipMounts {
			return fs.SkipAll
		}
		return filepath.SkipDir
	})
	return dirs
}
