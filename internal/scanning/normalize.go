package scanning

import (
	"encoding/json"
	"strings"

	"bugcode-shield/internal/finding"
)

func ptr[T any](v T) *T { return &v }

func mapSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "blocker", "0":
		if raw == "0" {
			return "critical"
		}
		return "critical"
	case "error":
		return "high"
	case "high":
		return "high"
	case "medium", "warning", "moderate", "major":
		return "medium"
	case "low", "minor":
		return "low"
	default:
		return "info"
	}
}

func ParseSemgrep(scanID, projectID string, raw []byte) []finding.Finding {
	var doc struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
			End struct {
				Line int `json:"line"`
			} `json:"end"`
			Extra struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
				Lines    string `json:"lines"`
				Metadata struct {
					CWE        any    `json:"cwe"`
					Impact     string `json:"impact"`
					Category   string `json:"category"`
					Technology any    `json:"technology"`
					References any    `json:"references"`
					Source     string `json:"source"`
					Shortlink  string `json:"shortlink"`
				} `json:"metadata"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := make([]finding.Finding, 0, len(doc.Results))
	for _, r := range doc.Results {
		path := strings.TrimPrefix(r.Path, "/src/")
		cwe := cweFromAny(r.Extra.Metadata.CWE)
		item := finding.Finding{
			ScanID:      scanID,
			ProjectID:   projectID,
			Scanner:     "semgrep",
			RuleID:      r.CheckID,
			Title:       r.CheckID,
			Description: r.Extra.Message,
			Severity:    mapSeverity(r.Extra.Severity),
			FilePath:    ptr(path),
			StartLine:   ptr(r.Start.Line),
			EndLine:     ptr(r.End.Line),
			Snippet:     ptr(trimSnippet(r.Extra.Lines)),
			Remediation: ptr("Review this code path and apply the secure alternative recommended by the Semgrep rule. Avoid untrusted input in dangerous sinks."),
			Raw:         json.RawMessage(`{}`),
		}
		if cwe != "" {
			item.CWE = ptr(cwe)
		}
		item.Fingerprint = finding.Fingerprint(item.Scanner, item.RuleID, path, r.Start.Line)
		out = append(out, item)
	}
	return out
}

func ParseTrivy(scanID, projectID string, raw []byte) []finding.Finding {
	var doc struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string `json:"VulnerabilityID"`
				PkgName          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
				Description      string `json:"Description"`
				PrimaryURL       string `json:"PrimaryURL"`
			} `json:"Vulnerabilities"`
			Misconfigurations []struct {
				ID          string `json:"ID"`
				Title       string `json:"Title"`
				Description string `json:"Description"`
				Severity    string `json:"Severity"`
				Message     string `json:"Message"`
				Resolution  string `json:"Resolution"`
			} `json:"Misconfigurations"`
			Secrets []struct {
				RuleID    string `json:"RuleID"`
				Category  string `json:"Category"`
				Severity  string `json:"Severity"`
				Title     string `json:"Title"`
				StartLine int    `json:"StartLine"`
				EndLine   int    `json:"EndLine"`
				Match     string `json:"Match"`
			} `json:"Secrets"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := make([]finding.Finding, 0)
	for _, result := range doc.Results {
		for _, v := range result.Vulnerabilities {
			title := v.Title
			if title == "" {
				title = v.VulnerabilityID
			}
			rem := "Upgrade " + v.PkgName
			if v.FixedVersion != "" {
				rem += " to " + v.FixedVersion
			}
			item := finding.Finding{
				ScanID:      scanID,
				ProjectID:   projectID,
				Scanner:     "trivy",
				RuleID:      v.VulnerabilityID,
				Title:       title,
				Description: strings.TrimSpace(v.PkgName + " " + v.InstalledVersion + " " + v.Description),
				Severity:    mapSeverity(v.Severity),
				CVE:         ptr(v.VulnerabilityID),
				FilePath:    ptr(result.Target),
				Remediation: ptr(rem),
			}
			item.Fingerprint = finding.Fingerprint(item.Scanner, item.RuleID, result.Target+"|"+v.PkgName, 0)
			out = append(out, item)
		}
		for _, m := range result.Misconfigurations {
			item := finding.Finding{
				ScanID:      scanID,
				ProjectID:   projectID,
				Scanner:     "trivy",
				RuleID:      m.ID,
				Title:       m.Title,
				Description: m.Description + " " + m.Message,
				Severity:    mapSeverity(m.Severity),
				FilePath:    ptr(result.Target),
				Remediation: ptr(m.Resolution),
			}
			item.Fingerprint = finding.Fingerprint(item.Scanner, item.RuleID, result.Target, 0)
			out = append(out, item)
		}
		for _, sec := range result.Secrets {
			title := sec.Title
			if title == "" {
				title = sec.RuleID
			}
			item := finding.Finding{
				ScanID:      scanID,
				ProjectID:   projectID,
				Scanner:     "trivy",
				RuleID:      sec.RuleID,
				Title:       title,
				Description: "Potential secret detected by Trivy. Rotate it if it is real; the value is redacted in BugCode Shield.",
				Severity:    mapSeverity(sec.Severity),
				FilePath:    ptr(result.Target),
				Snippet:     ptr(redactSecret(sec.Match)),
				Remediation: ptr("Remove the secret from source, rotate it, and load it from a secret manager."),
			}
			if sec.StartLine > 0 {
				item.StartLine = ptr(sec.StartLine)
			}
			if sec.EndLine > 0 {
				item.EndLine = ptr(sec.EndLine)
			}
			line := sec.StartLine
			item.Fingerprint = finding.Fingerprint(item.Scanner, item.RuleID, result.Target, line)
			out = append(out, item)
		}
	}
	return out
}

func ParseGitleaks(scanID, projectID string, raw []byte) []finding.Finding {
	type leak struct {
		RuleID      string `json:"RuleID"`
		Description string `json:"Description"`
		File        string `json:"File"`
		StartLine   int    `json:"StartLine"`
		EndLine     int    `json:"EndLine"`
		Secret      string `json:"Secret"`
		Match       string `json:"Match"`
	}
	var leaks []leak
	if err := json.Unmarshal(raw, &leaks); err != nil {
		var wrapped struct {
			Findings []leak `json:"findings"`
			Leaks    []leak `json:"leaks"`
		}
		if wrapErr := json.Unmarshal(raw, &wrapped); wrapErr != nil {
			return nil
		}
		leaks = wrapped.Findings
		if len(leaks) == 0 {
			leaks = wrapped.Leaks
		}
	}
	out := make([]finding.Finding, 0, len(leaks))
	for _, leak := range leaks {
		path := strings.TrimPrefix(leak.File, "/src/")
		item := finding.Finding{
			ScanID:      scanID,
			ProjectID:   projectID,
			Scanner:     "gitleaks",
			RuleID:      leak.RuleID,
			Title:       leak.Description,
			Description: "Potential secret detected. The value is redacted in BugCode Shield and should be rotated if it is real.",
			Severity:    "high",
			FilePath:    ptr(path),
			StartLine:   ptr(leak.StartLine),
			EndLine:     ptr(leak.EndLine),
			Snippet:     ptr(redactSecret(leak.Secret)),
			Remediation: ptr("Rotate the credential, remove it from source history, and store it in a secret manager."),
		}
		item.Fingerprint = finding.Fingerprint(item.Scanner, item.RuleID, path, leak.StartLine)
		out = append(out, item)
	}
	return out
}

func ParseDependencyCheck(scanID, projectID string, raw []byte) []finding.Finding {
	var doc struct {
		Dependencies []struct {
			FileName        string `json:"fileName"`
			FilePath        string `json:"filePath"`
			Vulnerabilities []struct {
				Name        string `json:"name"`
				Severity    string `json:"severity"`
				Description string `json:"description"`
				Cwe         string `json:"cwe"`
			} `json:"vulnerabilities"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := make([]finding.Finding, 0)
	for _, dep := range doc.Dependencies {
		for _, v := range dep.Vulnerabilities {
			item := finding.Finding{
				ScanID:      scanID,
				ProjectID:   projectID,
				Scanner:     "dependency-check",
				RuleID:      v.Name,
				Title:       v.Name + " in " + dep.FileName,
				Description: v.Description,
				Severity:    mapSeverity(v.Severity),
				FilePath:    ptr(dep.FilePath),
				Remediation: ptr("Upgrade the dependency to a non-vulnerable version and regenerate the lockfile."),
			}
			if v.Cwe != "" {
				item.CWE = ptr(v.Cwe)
			}
			if strings.HasPrefix(strings.ToUpper(v.Name), "CVE-") {
				item.CVE = ptr(v.Name)
			}
			item.Fingerprint = finding.Fingerprint(item.Scanner, item.RuleID, dep.FileName, 0)
			out = append(out, item)
		}
	}
	return out
}

func ParseSonarQube(scanID, projectID string, raw []byte) []finding.Finding {
	var doc struct {
		Issues []struct {
			Key         string `json:"key"`
			Rule        string `json:"rule"`
			Severity    string `json:"severity"`
			Type        string `json:"type"`
			Message     string `json:"message"`
			Component   string `json:"component"`
			Project     string `json:"project"`
			Line        int    `json:"line"`
			Status      string `json:"status"`
			IssueStatus string `json:"issueStatus"`
			TextRange   struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
			} `json:"textRange"`
			Impacts []struct {
				SoftwareQuality string `json:"softwareQuality"`
				Severity        string `json:"severity"`
			} `json:"impacts"`
		} `json:"issues"`
		Hotspots []struct {
			Key                      string `json:"key"`
			Component                string `json:"component"`
			Project                  string `json:"project"`
			VulnerabilityProbability string `json:"vulnerabilityProbability"`
			Status                   string `json:"status"`
			Line                     int    `json:"line"`
			Message                  string `json:"message"`
			RuleKey                  string `json:"ruleKey"`
		} `json:"hotspots"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	out := make([]finding.Finding, 0, len(doc.Issues)+len(doc.Hotspots))
	for _, issue := range doc.Issues {
		if sonarIssueClosed(issue.Status, issue.IssueStatus) {
			continue
		}
		path := sonarFilePath(issue.Component, issue.Project)
		start := issue.Line
		end := issue.Line
		if issue.TextRange.StartLine > 0 {
			start = issue.TextRange.StartLine
			end = issue.TextRange.EndLine
		}
		rule := issue.Rule
		if rule == "" {
			rule = issue.Key
		}
		item := finding.Finding{
			ScanID:      scanID,
			ProjectID:   projectID,
			Scanner:     "sonarqube",
			RuleID:      rule,
			Title:       rule,
			Description: issue.Message,
			Severity:    sonarIssueSeverity(issue.Severity, issue.Type, issue.Impacts),
			FilePath:    ptr(path),
			Remediation: ptr(sonarRemediation(issue.Type)),
		}
		if start > 0 {
			item.StartLine = ptr(start)
		}
		if end > 0 {
			item.EndLine = ptr(end)
		}
		item.Fingerprint = finding.Fingerprint(item.Scanner, item.RuleID, path, start)
		out = append(out, item)
	}
	for _, hs := range doc.Hotspots {
		if strings.EqualFold(hs.Status, "REVIEWED") {
			continue
		}
		path := sonarFilePath(hs.Component, hs.Project)
		rule := hs.RuleKey
		if rule == "" {
			rule = hs.Key
		}
		item := finding.Finding{
			ScanID:      scanID,
			ProjectID:   projectID,
			Scanner:     "sonarqube",
			RuleID:      rule,
			Title:       rule,
			Description: hs.Message,
			Severity:    mapSeverity(hs.VulnerabilityProbability),
			FilePath:    ptr(path),
			Remediation: ptr(sonarRemediation("SECURITY_HOTSPOT")),
		}
		if hs.Line > 0 {
			item.StartLine = ptr(hs.Line)
			item.EndLine = ptr(hs.Line)
		}
		item.Fingerprint = finding.Fingerprint(item.Scanner, item.RuleID, path, hs.Line)
		out = append(out, item)
	}
	return out
}

func sonarIssueClosed(status, issueStatus string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "CLOSED", "RESOLVED", "REVIEWED":
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(issueStatus)) {
	case "CLOSED", "FIXED", "FALSE_POSITIVE", "ACCEPTED":
		return true
	}
	return false
}

func sonarFilePath(component, projectKey string) string {
	path := component
	if projectKey != "" {
		path = strings.TrimPrefix(path, projectKey+":")
	}
	if i := strings.Index(path, ":"); i >= 0 {
		path = path[i+1:]
	}
	return strings.TrimPrefix(path, "/src/")
}

func sonarIssueSeverity(classic, issueType string, impacts []struct {
	SoftwareQuality string `json:"softwareQuality"`
	Severity        string `json:"severity"`
}) string {
	for _, imp := range impacts {
		if strings.EqualFold(imp.SoftwareQuality, "SECURITY") && imp.Severity != "" {
			return mapSeverity(imp.Severity)
		}
	}
	if classic != "" {
		return mapSeverity(classic)
	}
	if len(impacts) > 0 && impacts[0].Severity != "" {
		return mapSeverity(impacts[0].Severity)
	}
	if strings.EqualFold(issueType, "VULNERABILITY") {
		return "high"
	}
	return "info"
}

func sonarRemediation(issueType string) string {
	switch strings.ToUpper(issueType) {
	case "VULNERABILITY", "SECURITY_HOTSPOT":
		return "Review this security finding and apply the secure alternative recommended by the SonarQube rule."
	case "BUG":
		return "Fix the reliability issue described by this SonarQube rule."
	default:
		return "Refactor this code to match the SonarQube quality rule."
	}
}

func cweFromAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			if s, ok := t[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

func trimSnippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 4000 {
		return s[:4000]
	}
	return s
}

func redactSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "[redacted]"
	}
	if len(secret) <= 6 {
		return "******"
	}
	return secret[:2] + strings.Repeat("*", len(secret)-4) + secret[len(secret)-2:]
}
