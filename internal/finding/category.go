package finding

import "strings"

const (
	CategorySecurityHotspot = "security_hotspot"
	CategoryVulnerability   = "vulnerability"
	CategoryInfrastructure  = "infrastructure"
	CategorySecretLeak      = "secret_leak"
	CategoryDuplication     = "duplication"
	CategoryCodeQuality     = "code_quality"
)

type ClassifyInput struct {
	Scanner     string
	RuleID      string
	Title       string
	Description string
	Remediation string
	IssueType   string
	CVE         string
}

func NormalizeCategory(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case CategorySecurityHotspot, "hotspot", "security hotspot", "security_hotspots":
		return CategorySecurityHotspot
	case CategoryVulnerability, "vulnerabilities", "cve":
		return CategoryVulnerability
	case CategoryInfrastructure, "infra", "misconfiguration", "misconfig":
		return CategoryInfrastructure
	case CategorySecretLeak, "secret", "secrets", "secret_leak_detection":
		return CategorySecretLeak
	case CategoryDuplication, "duplicate", "duplicates":
		return CategoryDuplication
	case CategoryCodeQuality, "quality", "bug", "code_smell", "maintainability":
		return CategoryCodeQuality
	default:
		return ""
	}
}

func Classify(in ClassifyInput) string {
	scanner := strings.ToLower(strings.TrimSpace(in.Scanner))
	issueType := strings.ToUpper(strings.TrimSpace(in.IssueType))
	blob := strings.ToLower(strings.Join([]string{in.RuleID, in.Title, in.Description}, " "))
	rem := strings.ToLower(in.Remediation)

	if looksLikeDuplication(in.RuleID, blob) {
		return CategoryDuplication
	}

	switch scanner {
	case "gitleaks":
		return CategorySecretLeak
	case "semgrep":
		if looksLikeSecret(blob, rem) {
			return CategorySecretLeak
		}
		return CategoryVulnerability
	case "dependency-check":
		return CategoryVulnerability
	case "trivy":
		if looksLikeSecret(blob, rem) {
			return CategorySecretLeak
		}
		if strings.TrimSpace(in.CVE) != "" {
			return CategoryVulnerability
		}
		return CategoryInfrastructure
	case "sonarqube":
		switch issueType {
		case "SECURITY_HOTSPOT":
			return CategorySecurityHotspot
		case "VULNERABILITY":
			return CategoryVulnerability
		case "BUG", "CODE_SMELL":
			return CategoryCodeQuality
		}
		if strings.Contains(rem, "security hotspot") {
			return CategorySecurityHotspot
		}
		if strings.Contains(rem, "security finding") {
			return CategoryVulnerability
		}
		return CategoryCodeQuality
	}

	if cat := NormalizeCategory(issueType); cat != "" {
		return cat
	}
	if looksLikeSecret(blob, rem) {
		return CategorySecretLeak
	}
	return CategoryVulnerability
}

func (f *Finding) EnsureCategory() {
	if f == nil {
		return
	}
	if cat := NormalizeCategory(f.Category); cat != "" {
		f.Category = cat
		return
	}
	cve, rem := "", ""
	if f.CVE != nil {
		cve = *f.CVE
	}
	if f.Remediation != nil {
		rem = *f.Remediation
	}
	f.Category = Classify(ClassifyInput{
		Scanner:     f.Scanner,
		RuleID:      f.RuleID,
		Title:       f.Title,
		Description: f.Description,
		Remediation: rem,
		CVE:         cve,
	})
}

func looksLikeDuplication(ruleID, blob string) bool {
	rule := strings.ToLower(ruleID)
	if strings.Contains(rule, "duplicatedblocks") || strings.Contains(rule, "duplication") {
		return true
	}
	return strings.Contains(blob, "duplicated code") || strings.Contains(blob, "duplicated block") || strings.Contains(blob, "duplicated line")
}

func looksLikeSecret(blob, rem string) bool {
	if strings.Contains(blob, "secret") || strings.Contains(blob, "hardcoded password") || (strings.Contains(blob, "api key") && strings.Contains(blob, "hardcoded")) {
		return true
	}
	return strings.Contains(rem, "rotate the credential") || strings.Contains(rem, "secret manager")
}
