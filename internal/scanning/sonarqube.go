package scanning

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	sonarScannerImage = "sonarsource/sonar-scanner-cli:11"
	sonarTokenName    = "bugcodeshield-worker"
)

var sonarHTTP = &http.Client{Timeout: 30 * time.Second}

func sonarProjectKey(scanID string) string {
	cleaned := strings.ReplaceAll(scanID, "-", "")
	if cleaned == "" {
		cleaned = "scan"
	}
	return "bcs-" + cleaned
}

func (r *Runner) ensureSonarToken(ctx context.Context) (string, error) {
	if strings.TrimSpace(r.SonarURL) == "" {
		return "", fmt.Errorf("SonarQube is not configured; set SONARQUBE_URL")
	}
	r.sonarMu.Lock()
	defer r.sonarMu.Unlock()
	if r.sonarToken != "" {
		if err := r.sonarReady(ctx); err == nil {
			if ok, _ := r.sonarValid(ctx, "", "", r.sonarToken); ok {
				return r.sonarToken, nil
			}
		}
		r.sonarToken = ""
	}
	if err := r.waitSonarUp(ctx); err != nil {
		return "", err
	}
	user, pass, err := r.sonarAdmin(ctx)
	if err != nil {
		return "", err
	}
	token, err := r.sonarCreateToken(ctx, user, pass)
	if err != nil {
		return "", err
	}
	r.sonarToken = token
	return token, nil
}

func (r *Runner) waitSonarUp(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	if err := r.sonarReady(ctx); err == nil {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("SonarQube did not become ready at %s (is the sonarqube Compose service running?)", r.SonarURL)
		case <-ticker.C:
			if err := r.sonarReady(ctx); err == nil {
				return nil
			}
		}
	}
}

func (r *Runner) sonarReady(ctx context.Context) error {
	body, status, err := r.sonarDo(ctx, http.MethodGet, "/api/system/status", "", "", "", "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d", status)
	}
	var doc struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	if !strings.EqualFold(doc.Status, "UP") {
		return fmt.Errorf("sonarqube status %s", doc.Status)
	}
	return nil
}

func (r *Runner) sonarAdmin(ctx context.Context) (user, pass string, err error) {
	user = "admin"
	pass = strings.TrimSpace(r.SonarPassword)
	if pass != "" {
		if ok, _ := r.sonarValid(ctx, user, pass, ""); ok {
			return user, pass, nil
		}
	}
	if ok, _ := r.sonarValid(ctx, user, "admin", ""); ok {
		if pass == "" {
			return "", "", fmt.Errorf("set SONARQUBE_ADMIN_PASSWORD (SonarQube still has the default admin password)")
		}
		form := url.Values{
			"login":            {"admin"},
			"previousPassword": {"admin"},
			"password":         {pass},
		}
		_, status, changeErr := r.sonarForm(ctx, "/api/users/change_password", form, user, "admin", "")
		if changeErr != nil {
			return "", "", fmt.Errorf("change SonarQube admin password: %w", changeErr)
		}
		if status >= 300 {
			return "", "", fmt.Errorf("change SonarQube admin password: HTTP %d", status)
		}
		if ok, _ := r.sonarValid(ctx, user, pass, ""); ok {
			return user, pass, nil
		}
	}
	return "", "", fmt.Errorf("cannot authenticate to SonarQube; check SONARQUBE_ADMIN_PASSWORD")
}

func (r *Runner) sonarValid(ctx context.Context, user, pass, token string) (bool, error) {
	body, status, err := r.sonarDo(ctx, http.MethodGet, "/api/authentication/validate", "", user, pass, token)
	if err != nil {
		return false, err
	}
	if status != http.StatusOK {
		return false, nil
	}
	var doc struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return false, err
	}
	return doc.Valid, nil
}

func (r *Runner) sonarCreateToken(ctx context.Context, user, pass string) (string, error) {
	form := url.Values{"name": {sonarTokenName}}
	_, _, _ = r.sonarForm(ctx, "/api/user_tokens/revoke", form, user, pass, "")
	body, status, err := r.sonarForm(ctx, "/api/user_tokens/generate", form, user, pass, "")
	if err != nil {
		return "", fmt.Errorf("generate SonarQube token: %w", err)
	}
	if status >= 300 {
		return "", fmt.Errorf("generate SonarQube token: HTTP %d %s", status, truncate(string(body), 200))
	}
	var doc struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || strings.TrimSpace(doc.Token) == "" {
		return "", fmt.Errorf("generate SonarQube token: empty response")
	}
	return doc.Token, nil
}

func (r *Runner) collectSonarQube(ctx context.Context, scanID, localOut string) ([]byte, error) {
	token, err := r.ensureSonarToken(ctx)
	if err != nil {
		return nil, err
	}
	key := sonarProjectKey(scanID)
	taskID := readReportTask(filepath.Join(localOut, "report-task.txt"))
	if taskID == "" {
		return nil, fmt.Errorf("sonar-scanner did not finish analysis")
	}
	if err := r.waitComputeEngine(ctx, token, taskID); err != nil {
		return nil, err
	}
	var last []byte
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
		issues, err := r.fetchSonarIssues(ctx, token, key)
		if err != nil {
			return nil, err
		}
		hotspots, err := r.fetchSonarHotspots(ctx, token, key)
		if err != nil {
			hotspots = nil
		}
		duplications, err := r.fetchSonarDuplications(ctx, token, key)
		if err != nil {
			duplications = nil
		}
		out, err := json.Marshal(map[string]any{"issues": issues, "hotspots": hotspots, "duplications": duplications})
		if err != nil {
			return nil, err
		}
		last = out
		if len(issues)+len(hotspots)+len(duplications) > 0 {
			return out, nil
		}
	}
	if last == nil {
		last = []byte(`{"issues":[],"hotspots":[],"duplications":[]}`)
	}
	return last, nil
}

func readReportTask(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && k == "ceTaskId" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (r *Runner) waitComputeEngine(ctx context.Context, token, taskID string) error {
	q := url.Values{"id": {taskID}}.Encode()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		body, status, err := r.sonarDo(ctx, http.MethodGet, "/api/ce/task", q, "", "", token)
		if err == nil && status == http.StatusOK {
			var doc struct {
				Task struct {
					Status string `json:"status"`
					Error  string `json:"errorMessage"`
				} `json:"task"`
			}
			if json.Unmarshal(body, &doc) == nil {
				switch strings.ToUpper(doc.Task.Status) {
				case "SUCCESS":
					return nil
				case "FAILED", "CANCELED":
					msg := doc.Task.Error
					if msg == "" {
						msg = doc.Task.Status
					}
					return fmt.Errorf("SonarQube analysis %s", msg)
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for SonarQube analysis")
		case <-ticker.C:
		}
	}
}

func (r *Runner) fetchSonarIssues(ctx context.Context, token, projectKey string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0)
	for page := 1; page <= 20; page++ {
		q := url.Values{
			"components": {projectKey},
			"ps":         {"500"},
			"p":          {fmt.Sprintf("%d", page)},
		}.Encode()
		body, status, err := r.sonarDo(ctx, http.MethodGet, "/api/issues/search", q, "", "", token)
		if err != nil {
			return nil, err
		}
		if status >= 300 {
			return nil, fmt.Errorf("issues search HTTP %d %s", status, truncate(string(body), 200))
		}
		var doc struct {
			Issues []json.RawMessage `json:"issues"`
			Paging struct {
				Total int `json:"total"`
			} `json:"paging"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, err
		}
		out = append(out, doc.Issues...)
		if page*500 >= doc.Paging.Total || len(doc.Issues) == 0 {
			break
		}
	}
	return out, nil
}

func (r *Runner) fetchSonarHotspots(ctx context.Context, token, projectKey string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0)
	for page := 1; page <= 20; page++ {
		q := url.Values{
			"project": {projectKey},
			"ps":      {"500"},
			"p":       {fmt.Sprintf("%d", page)},
		}.Encode()
		body, status, err := r.sonarDo(ctx, http.MethodGet, "/api/hotspots/search", q, "", "", token)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound || status == http.StatusBadRequest {
			return out, nil
		}
		if status >= 300 {
			return nil, fmt.Errorf("hotspots search HTTP %d %s", status, truncate(string(body), 200))
		}
		var doc struct {
			Hotspots []json.RawMessage `json:"hotspots"`
			Paging   struct {
				Total int `json:"total"`
			} `json:"paging"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, err
		}
		out = append(out, doc.Hotspots...)
		if page*500 >= doc.Paging.Total || len(doc.Hotspots) == 0 {
			break
		}
	}
	return out, nil
}

func (r *Runner) fetchSonarDuplications(ctx context.Context, token, projectKey string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0)
	for page := 1; page <= 20; page++ {
		q := url.Values{
			"component":  {projectKey},
			"metricKeys": {"duplicated_blocks,duplicated_lines,duplicated_lines_density"},
			"strategy":   {"leaves"},
			"ps":         {"500"},
			"p":          {fmt.Sprintf("%d", page)},
		}.Encode()
		body, status, err := r.sonarDo(ctx, http.MethodGet, "/api/measures/component_tree", q, "", "", token)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound || status == http.StatusBadRequest {
			return out, nil
		}
		if status >= 300 {
			return nil, fmt.Errorf("duplication measures HTTP %d %s", status, truncate(string(body), 200))
		}
		var doc struct {
			Components []json.RawMessage `json:"components"`
			Paging     struct {
				Total int `json:"total"`
			} `json:"paging"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, err
		}
		out = append(out, doc.Components...)
		if page*500 >= doc.Paging.Total || len(doc.Components) == 0 {
			break
		}
	}
	return out, nil
}

func (r *Runner) sonarForm(ctx context.Context, path string, form url.Values, user, pass, token string) ([]byte, int, error) {
	u := strings.TrimRight(r.SonarURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	applySonarAuth(req, user, pass, token)
	return readSonarResponse(req)
}

func (r *Runner) sonarDo(ctx context.Context, method, path, rawQuery, user, pass, token string) ([]byte, int, error) {
	u := strings.TrimRight(r.SonarURL, "/") + path
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	applySonarAuth(req, user, pass, token)
	return readSonarResponse(req)
}

func applySonarAuth(req *http.Request, user, pass, token string) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		return
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
}

func readSonarResponse(req *http.Request) ([]byte, int, error) {
	res, err := sonarHTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, res.StatusCode, err
	}
	return body, res.StatusCode, nil
}
