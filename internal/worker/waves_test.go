package worker

import "testing"

func TestSplitScanWavesRunsSonarLast(t *testing.T) {
	first, second := splitScanWaves([]string{"semgrep", "trivy", "gitleaks", "sonarqube", "dependency-check"})
	if got := join(first); got != "semgrep,trivy,gitleaks,dependency-check" {
		t.Fatalf("first=%s", got)
	}
	if got := join(second); got != "sonarqube" {
		t.Fatalf("second=%s", got)
	}

	first, second = splitScanWaves([]string{"sonarqube"})
	if len(first) != 0 || join(second) != "sonarqube" {
		t.Fatalf("sonar-only first=%v second=%v", first, second)
	}

	first, second = splitScanWaves([]string{"semgrep", "trivy"})
	if join(first) != "semgrep,trivy" || len(second) != 0 {
		t.Fatalf("cli-only first=%v second=%v", first, second)
	}
}

func join(items []string) string {
	out := ""
	for i, item := range items {
		if i > 0 {
			out += ","
		}
		out += item
	}
	return out
}
