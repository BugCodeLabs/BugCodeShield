package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifyGitHubRepoSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/octocat/hello-world":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"full_name":"octocat/hello-world"}`))
		case strings.HasPrefix(r.URL.Path, "/repos/octocat/hello-world/commits/"):
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "abc123def456"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	orig := githubAPIBase
	githubAPIBase = srv.URL
	t.Cleanup(func() { githubAPIBase = orig })

	sha, err := verifyGitHubRepo(context.Background(), "https://github.com/octocat/hello-world", "main", "")
	if err != nil {
		t.Fatal(err)
	}
	if sha != "abc123def456" {
		t.Fatalf("sha = %q", sha)
	}
}

func TestVerifyGitHubRepoMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	t.Cleanup(srv.Close)
	orig := githubAPIBase
	githubAPIBase = srv.URL
	t.Cleanup(func() { githubAPIBase = orig })

	_, err := verifyGitHubRepo(context.Background(), "missing/repo", "main", "")
	if err == nil {
		t.Fatal("expected missing repo to fail")
	}
}
