package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var githubAPIBase = "https://api.github.com"

func verifyGitHubRepo(ctx context.Context, repo, ref, token string) (commitSHA string, err error) {
	repo = NormalizeGitHubRepo(repo)
	if repo == "" {
		return "", fmt.Errorf("repository must look like owner/name or a github.com URL")
	}
	client := &http.Client{Timeout: 12 * time.Second}

	repoURL := githubAPIBase + "/repos/" + repo
	status, body, err := githubGET(ctx, client, repoURL, token)
	if err != nil {
		return "", fmt.Errorf("could not reach GitHub to verify the repository")
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", fmt.Errorf("GitHub repository not found, or it is private. Add a GitHub token in Settings")
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", fmt.Errorf("GitHub rejected access. Check the token and repository permissions")
	default:
		return "", fmt.Errorf("GitHub could not verify this repository")
	}

	commitURL := githubAPIBase + "/repos/" + repo + "/commits/" + url.PathEscape(ref)
	status, body, err = githubGET(ctx, client, commitURL, token)
	if err != nil {
		return "", fmt.Errorf("repository exists, but GitHub could not be reached to check branch %s", ref)
	}
	if status == http.StatusNotFound {
		return "", fmt.Errorf("repository found, but branch or ref %q was not found", ref)
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return "", fmt.Errorf("GitHub rejected access while checking branch %s", ref)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("could not verify branch %s on GitHub", ref)
	}
	var doc struct {
		SHA string `json:"sha"`
	}
	if json.Unmarshal(body, &doc) == nil {
		return doc.SHA, nil
	}
	return "", nil
}

func githubGET(ctx context.Context, client *http.Client, rawURL, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "BugCode-Shield")
	req.Header.Set("Accept", "application/vnd.github+json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}
