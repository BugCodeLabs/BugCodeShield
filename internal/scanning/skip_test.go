package scanning

import (
	"strings"
	"testing"

	"bugcode-shield/internal/source"
)

func TestCommandForExcludesAllLanguageSkipDirs(t *testing.T) {
	required := []string{".nx", "node_modules", ".git", "dist", "coverage", ".next", ".turbo", ".cache", "vendor", "target", "venv", "__pycache__", "bin", "obj"}
	_, semgrep := commandFor("semgrep", "scan-1")
	joined := strings.Join(semgrep, "\n")
	for _, name := range required {
		if !strings.Contains(joined, name) {
			t.Errorf("semgrep args missing skip dir %q", name)
		}
	}
	_, trivy := commandFor("trivy", "scan-1")
	joined = strings.Join(trivy, "\n")
	for _, name := range required {
		if !strings.Contains(joined, name) {
			t.Errorf("trivy args missing skip dir %q", name)
		}
	}
	cfg := gitleaksConfig()
	for _, name := range required {
		if !strings.Contains(cfg, name) {
			t.Errorf("gitleaks config missing skip dir %q", name)
		}
	}
	exclusions := sonarExclusions()
	for _, glob := range source.SkipGlobs() {
		if !strings.Contains(exclusions, glob) {
			t.Errorf("sonar exclusions missing %q", glob)
		}
	}
}
