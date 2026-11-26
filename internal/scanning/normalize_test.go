package scanning

import (
	"strings"
	"testing"
)

func TestRedactSecretNeverShowsFullValue(t *testing.T) {
	got := redactSecret("ghp_exampleexampleexample")
	if got == "ghp_exampleexampleexample" {
		t.Fatal("secret was not redacted")
	}
	if got[:2] != "gh" || got[len(got)-2:] != "le" {
		t.Fatalf("unexpected redaction %q", got)
	}
}

func TestMapSeverity(t *testing.T) {
	if mapSeverity("CRITICAL") != "critical" {
		t.Fatal(mapSeverity("CRITICAL"))
	}
	if mapSeverity("warning") != "medium" {
		t.Fatal(mapSeverity("warning"))
	}
	if mapSeverity("BLOCKER") != "critical" {
		t.Fatal(mapSeverity("BLOCKER"))
	}
	if mapSeverity("MAJOR") != "medium" {
		t.Fatal(mapSeverity("MAJOR"))
	}
}

func TestParseGitleaksRedactsSecret(t *testing.T) {
	raw := []byte(`[{"RuleID":"aws-access-key","Description":"AWS Access Key","File":"/src/.env.example","StartLine":2,"EndLine":2,"Secret":"AKIA0TESTKEYTESTKEY"}]`)
	got := ParseGitleaks("scan-1", "proj-1", raw)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Snippet == nil || *got[0].Snippet == "AKIA0TESTKEYTESTKEY" {
		t.Fatal("secret was not redacted")
	}
	if got[0].Severity != "high" {
		t.Fatalf("severity %s", got[0].Severity)
	}
	if got[0].Category != "secret_leak" {
		t.Fatalf("category %s", got[0].Category)
	}
}

func TestParseSemgrep(t *testing.T) {
	raw := []byte(`{"results":[{"check_id":"javascript.lang.security.audit.eval-detected","path":"/src/app.js","start":{"line":9},"end":{"line":9},"extra":{"message":"Detected eval","severity":"WARNING","lines":"eval(q)"}}]}`)
	got := ParseSemgrep("scan-1", "proj-1", raw)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != "medium" {
		t.Fatalf("severity %s", got[0].Severity)
	}
	if got[0].Category != "vulnerability" {
		t.Fatalf("category %s", got[0].Category)
	}
	if got[0].FilePath == nil || *got[0].FilePath != "app.js" {
		t.Fatalf("path %+v", got[0].FilePath)
	}
}

func TestParseTrivySecrets(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":".env","Secrets":[{"RuleID":"aws-access-key-id","Severity":"CRITICAL","Title":"AWS Access Key ID","StartLine":2,"EndLine":2,"Match":"AKIA0TESTKEYTESTKEY"}]}]}`)
	got := ParseTrivy("scan-1", "proj-1", raw)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != "critical" {
		t.Fatalf("severity %s", got[0].Severity)
	}
	if got[0].Snippet == nil || *got[0].Snippet == "AKIA0TESTKEYTESTKEY" {
		t.Fatal("secret was not redacted")
	}
	if got[0].Category != "secret_leak" {
		t.Fatalf("category %s", got[0].Category)
	}
}

func TestParseTrivyCategories(t *testing.T) {
	raw := []byte(`{"Results":[
		{"Target":"go.mod","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1","PkgName":"demo","InstalledVersion":"1.0","Severity":"HIGH","Title":"demo CVE"}]},
		{"Target":"Dockerfile","Misconfigurations":[{"ID":"DS002","Title":"root user","Description":"user","Severity":"MEDIUM","Message":"do not run as root","Resolution":"use non-root"}]}
	]}`)
	got := ParseTrivy("scan-1", "proj-1", raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(got))
	}
	if got[0].Category != "vulnerability" {
		t.Fatalf("cve category %s", got[0].Category)
	}
	if got[1].Category != "infrastructure" {
		t.Fatalf("misconfig category %s", got[1].Category)
	}
}

func TestSanitizeScannerLogStripsANSI(t *testing.T) {
	got := sanitizeScannerLog("\x1b[32mINF\x1b[0m no leaks found\nSecret: AKIA0TESTKEYTESTKEY")
	if strings.Contains(got, "\x1b") || strings.Contains(got, "[32m") {
		t.Fatalf("ansi left in %q", got)
	}
	if strings.Contains(got, "AKIA0TESTKEYTESTKEY") {
		t.Fatal("secret leaked into scanner log")
	}
}

func TestSanitizeScannerLogKeepsErrors(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 80; i++ {
		b.WriteString("INFO startup line\n")
	}
	b.WriteString("ERROR The analysis will stop due to the Node.js process running out of memory\n")
	b.WriteString("INFO EXECUTION FAILURE\n")
	got := sanitizeScannerLog(b.String())
	if !strings.Contains(got, "Node.js process running out of memory") {
		t.Fatalf("error dropped from %q", got)
	}
	if !strings.Contains(got, "EXECUTION FAILURE") {
		t.Fatalf("failure dropped from %q", got)
	}
}

func TestSonarProjectKey(t *testing.T) {
	if got := sonarProjectKey("abc-def"); got != "bcs-abcdef" {
		t.Fatalf("got %q", got)
	}
}

func TestParseSonarQube(t *testing.T) {
	raw := []byte(`{
		"issues":[
			{"key":"i1","rule":"javascript:S1523","severity":"CRITICAL","type":"VULNERABILITY","message":"Do not use eval","component":"bcs-scan:app.js","project":"bcs-scan","line":9,"textRange":{"startLine":9,"endLine":9},"impacts":[{"softwareQuality":"SECURITY","severity":"HIGH"}]},
			{"key":"i2","rule":"javascript:S1135","severity":"INFO","type":"CODE_SMELL","message":"closed","component":"bcs-scan:app.js","project":"bcs-scan","status":"CLOSED"}
		],
		"hotspots":[
			{"key":"h1","ruleKey":"javascript:S2068","component":"bcs-scan:app.js","project":"bcs-scan","vulnerabilityProbability":"HIGH","status":"TO_REVIEW","line":5,"message":"hardcoded secret"}
		],
		"duplications":[
			{"path":"lib.js","measures":[{"metric":"duplicated_blocks","value":"2"},{"metric":"duplicated_lines","value":"40"},{"metric":"duplicated_lines_density","value":"12.5"}]}
		]
	}`)
	got := ParseSonarQube("scan-1", "proj-1", raw)
	if len(got) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(got))
	}
	if got[0].Scanner != "sonarqube" || got[0].Severity != "high" || got[0].Category != "vulnerability" {
		t.Fatalf("issue %+v", got[0])
	}
	if got[0].FilePath == nil || *got[0].FilePath != "app.js" {
		t.Fatalf("path %+v", got[0].FilePath)
	}
	if got[1].RuleID != "javascript:S2068" || got[1].Severity != "high" || got[1].Category != "security_hotspot" {
		t.Fatalf("hotspot %+v", got[1])
	}
	if got[2].Category != "duplication" || got[2].FilePath == nil || *got[2].FilePath != "lib.js" {
		t.Fatalf("duplication %+v", got[2])
	}
}

func TestExtractJSON(t *testing.T) {
	got := extractJSON([]byte("banner\n[{\"a\":1}]\nleaks found: 1"))
	if string(got) != `[{"a":1}]` {
		t.Fatalf("got %q", got)
	}
}
