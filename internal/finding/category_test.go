package finding

import "testing"

func TestClassifyByScanner(t *testing.T) {
	cases := []struct {
		in   ClassifyInput
		want string
	}{
		{ClassifyInput{Scanner: "semgrep", RuleID: "javascript.lang.security.audit.eval-detected"}, CategoryVulnerability},
		{ClassifyInput{Scanner: "gitleaks", RuleID: "aws-access-key"}, CategorySecretLeak},
		{ClassifyInput{Scanner: "trivy", CVE: "CVE-2024-1234"}, CategoryVulnerability},
		{ClassifyInput{Scanner: "trivy", RuleID: "DS002", Title: "Image user should not be root"}, CategoryInfrastructure},
		{ClassifyInput{Scanner: "trivy", RuleID: "aws-access-key-id", Title: "AWS Access Key ID", Description: "Potential secret"}, CategorySecretLeak},
		{ClassifyInput{Scanner: "sonarqube", IssueType: "SECURITY_HOTSPOT"}, CategorySecurityHotspot},
		{ClassifyInput{Scanner: "sonarqube", IssueType: "VULNERABILITY"}, CategoryVulnerability},
		{ClassifyInput{Scanner: "sonarqube", IssueType: "CODE_SMELL"}, CategoryCodeQuality},
		{ClassifyInput{Scanner: "sonarqube", RuleID: "common-js:DuplicatedBlocks", Title: "Duplicated blocks"}, CategoryDuplication},
		{ClassifyInput{Scanner: "dependency-check", CVE: "CVE-2023-1"}, CategoryVulnerability},
	}
	for _, tc := range cases {
		got := Classify(tc.in)
		if got != tc.want {
			t.Fatalf("%+v: got %s want %s", tc.in, got, tc.want)
		}
	}
}

func TestEnsureCategoryFillsEmpty(t *testing.T) {
	f := Finding{Scanner: "gitleaks", RuleID: "generic-api-key", Title: "API key"}
	f.EnsureCategory()
	if f.Category != CategorySecretLeak {
		t.Fatalf("got %s", f.Category)
	}
}
