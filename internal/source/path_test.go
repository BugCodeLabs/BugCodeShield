package source

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAcceptsFolderUnderHome(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Projects", "app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := Paths{HostHome: home, ContainerHome: home}
	host, view, err := p.Resolve(dir)
	if err != nil {
		t.Fatal(err)
	}
	if host != dir || view != dir {
		t.Fatalf("host=%s view=%s", host, view)
	}
}

func TestResolveRejectsEtc(t *testing.T) {
	p := Paths{HostHome: t.TempDir(), ContainerHome: t.TempDir()}
	if _, _, err := p.Resolve("/etc/passwd"); err == nil {
		t.Fatal("expected /etc to be rejected")
	}
}

func TestResolveRejectsRelative(t *testing.T) {
	p := Paths{HostHome: t.TempDir(), ContainerHome: t.TempDir()}
	if _, _, err := p.Resolve("Projects/app"); err == nil {
		t.Fatal("expected relative path to be rejected")
	}
}

func TestFindByNameScoresChildren(t *testing.T) {
	home := t.TempDir()
	one := filepath.Join(home, "Desktop", "apply-goal-backend")
	two := filepath.Join(home, "Desktop", "other", "apply-goal-backend")
	if err := os.MkdirAll(filepath.Join(one, "apps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(two, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(one, "package.json"), []byte("{}"), 0o644)
	p := Paths{HostHome: home, ContainerHome: home}
	picked, matches, err := p.PickFolder("apply-goal-backend", []string{"apps", "package.json"})
	if err != nil {
		t.Fatal(err)
	}
	if picked != one {
		t.Fatalf("picked %s want %s (matches=%+v)", picked, one, matches)
	}
}

func TestPickFolderAsksWhenTied(t *testing.T) {
	home := t.TempDir()
	one := filepath.Join(home, "a", "demo")
	two := filepath.Join(home, "b", "demo")
	if err := os.MkdirAll(one, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(two, 0o755); err != nil {
		t.Fatal(err)
	}
	p := Paths{HostHome: home, ContainerHome: home}
	picked, matches, err := p.PickFolder("demo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if picked != "" {
		t.Fatalf("expected user choice, picked %s", picked)
	}
	if len(matches) != 2 {
		t.Fatalf("matches %d", len(matches))
	}
}

func TestCountScanFilesSkipsNodeModules(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "app.js"), []byte("ok"), 0o644)
	_ = os.MkdirAll(filepath.Join(root, "node_modules", "x"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "node_modules", "x", "index.js"), []byte("skip"), 0o644)
	n, _, err := CountScanFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("counted %d, want 1", n)
	}
}
