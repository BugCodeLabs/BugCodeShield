package scanning

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"bugcode-shield/internal/source"
)

type RunResult struct {
	Scanner  string
	Output   []byte
	Log      string
	Err      error
	ExitCode int
}

type Runner struct {
	HostWorkspace string
	HostCache     string
	ContainerSrc  string
	Network       string
	Timeout       time.Duration
	SonarURL      string
	SonarPassword string

	sonarMu    sync.Mutex
	sonarToken string
}

func (r *Runner) Run(ctx context.Context, scanner, scanID, hostSrc, hostOut, localOut string) RunResult {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	if scanner == "sonarqube" && timeout < 25*time.Minute {
		timeout = 25 * time.Minute
	}
	if localOut == "" {
		localOut = hostOut
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_ = os.MkdirAll(localOut, 0o777)
	_ = os.Chmod(localOut, 0o777)

	if scanner == "gitleaks" {
		_ = os.WriteFile(filepath.Join(localOut, "gitleaks.toml"), []byte(gitleaksConfig()), 0o644)
	}

	image, args := commandFor(scanner, scanID)
	if image == "" {
		return RunResult{Scanner: scanner, Err: fmt.Errorf("unsupported scanner %s", scanner)}
	}
	shortID := scanID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	name := fmt.Sprintf("bugcodeshield-%s-%s", scanner, shortID)
	ensureImage(ctx, image)

	memory, cpus, pids, tmpfs := "1536m", "1", "256", "2g"
	if scanner == "sonarqube" {
		memory, cpus, pids, tmpfs = "5g", "2", "2048", "4g"
	}

	dockerArgs := []string{
		"run", "--rm",
		"--name", name,
		"--memory", memory,
		"--cpus", cpus,
		"--pids-limit", pids,
		"--tmpfs", "/tmp:rw,exec,nosuid,size=" + tmpfs,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"-v", hostSrc + ":/src:ro",
		"-v", hostOut + ":/out",
	}
	dockerArgs = append(dockerArgs, skipDirVolumeArgs(hostSrc)...)
	if scanner == "trivy" && r.HostCache != "" {
		dockerArgs = append(dockerArgs,
			"-e", "TRIVY_CACHE_DIR=/cache",
			"-v", r.HostCache+":/cache",
		)
	} else {
		dockerArgs = append(dockerArgs, "-e", "TRIVY_CACHE_DIR=/tmp/trivy")
	}
	if scanner == "sonarqube" {
		token, err := r.ensureSonarToken(ctx)
		if err != nil {
			return RunResult{Scanner: scanner, Err: err}
		}
		dockerArgs = append(dockerArgs,
			"--user", "0:0",
			"-e", "SONAR_HOST_URL="+strings.TrimRight(r.SonarURL, "/"),
			"-e", "SONAR_TOKEN="+token,
			"-e", "SONAR_USER_HOME=/tmp/.sonar",
			"-e", "SONAR_SCANNER_OPTS=-Xmx1024m",
		)
	}
	network := r.Network
	if scanner == "sonarqube" && network == "" {
		network = "bugcode-shield_scanners"
	}
	if network != "" {
		dockerArgs = append(dockerArgs, "--network", network)
	}
	dockerArgs = append(dockerArgs, image)
	dockerArgs = append(dockerArgs, args...)

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	combined, err := cmd.CombinedOutput()
	res := RunResult{Scanner: scanner, Err: err, Log: sanitizeScannerLog(string(combined))}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if scanner == "sonarqube" {
		report, collectErr := r.collectSonarQube(ctx, scanID, localOut)
		if collectErr == nil && len(report) > 0 {
			res.Output = report
			_ = os.WriteFile(filepath.Join(localOut, "sonarqube.json"), report, 0o644)
			res.Err = nil
		} else if res.Err == nil && collectErr != nil {
			res.Err = fmt.Errorf("%s failed: %w", scanner, collectErr)
		}
	} else {
		outFile := outputFile(localOut, scanner)
		if data, readErr := os.ReadFile(outFile); readErr == nil && len(bytes.TrimSpace(data)) > 0 {
			res.Output = data
		} else if extracted := extractJSON(combined); len(extracted) > 0 {
			res.Output = extracted
		}
	}
	// Gitleaks (and some other scanners) exit 1 when they found issues.
	if res.ExitCode == 1 && len(res.Output) > 0 {
		res.Err = nil
	}
	if res.Err != nil && len(res.Output) == 0 && err != nil {
		res.Err = fmt.Errorf("%s failed: %w: %s", scanner, err, truncateTail(string(combined), 800))
	}
	return res
}

func ensureImage(ctx context.Context, image string) {
	if image == "" {
		return
	}
	if exec.CommandContext(ctx, "docker", "image", "inspect", image).Run() == nil {
		return
	}
	_ = exec.CommandContext(ctx, "docker", "pull", image).Run()
}

func commandFor(scanner, scanID string) (image string, args []string) {
	switch scanner {
	case "semgrep":
		args := []string{
			"semgrep", "scan",
			"--metrics", "off",
			"--disable-version-check",
			"--config", "p/default",
			"--config", "p/security-audit",
			"--config", "p/secrets",
			"--config", "p/owasp-top-ten",
			"--config", "p/javascript",
			"--config", "p/typescript",
			"--config", "p/python",
			"--config", "p/golang",
			"--config", "p/java",
			"--config", "p/php",
			"--config", "p/nodejs",
		}
		args = appendNamedSkipFlags(args, "--exclude")
		args = append(args, "--json", "--output", "/out/semgrep.json", "/src")
		return "semgrep/semgrep:1.97.0", args
	case "trivy":
		args := []string{"fs", "--scanners", "vuln,misconfig,secret"}
		for _, name := range source.SkipDirNames {
			args = append(args, "--skip-dirs", name, "--skip-dirs", "**/"+name)
		}
		args = append(args, "--quiet", "--format", "json", "--output", "/out/trivy.json", "/src")
		return "aquasec/trivy:0.58.1", args
	case "gitleaks":
		return "zricethezav/gitleaks:v8.21.2", []string{
			"detect",
			"--source", "/src",
			"--no-git",
			"--config", "/out/gitleaks.toml",
			"--report-format", "json",
			"--report-path", "/out/gitleaks.json",
		}
	case "dependency-check":
		args := []string{"--scan", "/src", "--format", "JSON", "--out", "/out", "--noupdate"}
		for _, glob := range source.SkipGlobs() {
			args = append(args, "--exclude", glob)
		}
		return "owasp/dependency-check:12.1.0", args
	case "sonarqube":
		key := sonarProjectKey(scanID)
		return sonarScannerImage, []string{
			"-Dsonar.projectKey=" + key,
			"-Dsonar.projectName=" + key,
			"-Dsonar.projectBaseDir=/src",
			"-Dsonar.sources=.",
			"-Dsonar.tests=.",
			"-Dsonar.scm.disabled=true",
			"-Dsonar.qualitygate.wait=false",
			"-Dsonar.javascript.node.maxspace=4096",
			"-Dsonar.scanner.metadataFilePath=/out/report-task.txt",
			"-Dsonar.exclusions=" + sonarExclusions(),
			"-Dsonar.test.inclusions=**/*.spec.ts,**/*.spec.tsx,**/*.spec.js,**/*.test.ts,**/*.test.tsx,**/*.test.js,**/*-e2e/**,**/e2e/**",
			"-Dsonar.test.exclusions=" + strings.Join(source.SkipGlobs(), ","),
		}
	default:
		return "", nil
	}
}

func skipDirVolumeArgs(hostSrc string) []string {
	dirs := source.FindSkipDirRelPaths(hostSrc)
	if len(dirs) == 0 {
		return nil
	}
	args := make([]string, 0, len(dirs)*2)
	for _, rel := range dirs {
		args = append(args, "-v", path.Join("/src", rel))
	}
	return args
}

func appendNamedSkipFlags(args []string, flag string) []string {
	for _, name := range source.SkipDirNames {
		args = append(args, flag, name)
	}
	return args
}

func sonarExclusions() string {
	extra := []string{
		"**/.husky/**",
		"**/*.min.js",
		"**/*.spec.ts",
		"**/*.spec.tsx",
		"**/*.spec.js",
		"**/*.test.ts",
		"**/*.test.tsx",
		"**/*.test.js",
		"**/*-e2e/**",
		"**/e2e/**",
	}
	return strings.Join(append(source.SkipGlobs(), extra...), ",")
}

func gitleaksConfig() string {
	var b strings.Builder
	b.WriteString("title = \"BugCode Shield\"\n\n[extend]\nuseDefault = true\n\n[allowlist]\npaths = [\n")
	for _, name := range source.SkipDirNames {
		b.WriteString("  '''(^|/)")
		b.WriteString(regexp.QuoteMeta(name))
		b.WriteString("/''',\n")
	}
	b.WriteString("]\n")
	return b.String()
}

func outputFile(outDir, scanner string) string {
	switch scanner {
	case "semgrep":
		return filepath.Join(outDir, "semgrep.json")
	case "trivy":
		return filepath.Join(outDir, "trivy.json")
	case "gitleaks":
		return filepath.Join(outDir, "gitleaks.json")
	case "dependency-check":
		matches, _ := filepath.Glob(filepath.Join(outDir, "*.json"))
		if len(matches) > 0 {
			return matches[0]
		}
		return filepath.Join(outDir, "dependency-check-report.json")
	case "sonarqube":
		return filepath.Join(outDir, "sonarqube.json")
	default:
		return filepath.Join(outDir, scanner+".json")
	}
}

func extractJSON(raw []byte) []byte {
	s := bytes.TrimSpace(raw)
	start := bytes.IndexAny(s, "{[")
	if start < 0 {
		return nil
	}
	s = s[start:]
	end := bytes.LastIndexAny(s, "}]")
	if end < 0 {
		return nil
	}
	candidate := bytes.TrimSpace(s[:end+1])
	if len(candidate) == 0 || (candidate[0] != '{' && candidate[0] != '[') {
		return nil
	}
	return candidate
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func truncateTail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func sanitizeScannerLog(s string) string {
	s = ansiEscape.ReplaceAllString(s, "")
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "secret:") || strings.Contains(lower, "x-access-token:") || strings.Contains(lower, "sonar.token=") {
			continue
		}
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
	}
	var kept []string
	for _, line := range lines {
		upper := strings.ToUpper(line)
		if strings.Contains(upper, " ERROR") || strings.Contains(upper, "ERROR ") || strings.Contains(upper, "EXCEPTION") || strings.Contains(upper, "EXECUTION FAILURE") {
			kept = append(kept, line)
		}
	}
	start := len(lines) - 25
	if start < 0 {
		start = 0
	}
	kept = append(kept, lines[start:]...)
	if len(kept) > 50 {
		kept = kept[len(kept)-50:]
	}
	return truncate(strings.Join(kept, "\n"), 2500)
}
