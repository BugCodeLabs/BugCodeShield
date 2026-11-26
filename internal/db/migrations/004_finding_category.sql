ALTER TABLE findings ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT '';

UPDATE findings SET category = CASE
    WHEN scanner = 'gitleaks' THEN 'secret_leak'
    WHEN scanner = 'dependency-check' THEN 'vulnerability'
    WHEN scanner = 'semgrep' AND (
        rule_id ILIKE '%secret%' OR title ILIKE '%secret%' OR description ILIKE '%secret%'
    ) THEN 'secret_leak'
    WHEN scanner = 'semgrep' THEN 'vulnerability'
    WHEN scanner = 'trivy' AND cve IS NOT NULL AND cve <> '' THEN 'vulnerability'
    WHEN scanner = 'trivy' AND (
        title ILIKE '%secret%' OR description ILIKE '%secret%' OR rule_id ILIKE '%secret%'
    ) THEN 'secret_leak'
    WHEN scanner = 'trivy' THEN 'infrastructure'
    WHEN scanner = 'sonarqube' AND (
        rule_id ILIKE '%duplicat%' OR title ILIKE '%duplicat%' OR description ILIKE '%duplicat%'
    ) THEN 'duplication'
    WHEN scanner = 'sonarqube' AND remediation ILIKE '%security hotspot%' THEN 'security_hotspot'
    WHEN scanner = 'sonarqube' AND remediation ILIKE '%security finding%' THEN 'vulnerability'
    WHEN scanner = 'sonarqube' THEN 'code_quality'
    ELSE 'vulnerability'
END
WHERE category = '';

CREATE INDEX IF NOT EXISTS findings_category_idx ON findings (category);
