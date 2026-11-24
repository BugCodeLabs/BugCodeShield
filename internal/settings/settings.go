package settings

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"bugcode-shield/internal/auth"
	"bugcode-shield/internal/crypto"
	"bugcode-shield/internal/httputil"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool   *pgxpool.Pool
	encKey []byte
}

func New(pool *pgxpool.Pool, encKey []byte) *Service {
	return &Service{pool: pool, encKey: encKey}
}

type View struct {
	GitHubTokenSet   bool   `json:"github_token_set"`
	GitHubTokenHint  string `json:"github_token_hint,omitempty"`
	OpenAIAPIKeySet  bool   `json:"openai_api_key_set"`
	OpenAIAPIKeyHint string `json:"openai_api_key_hint,omitempty"`
	OpenAIBaseURL    string `json:"openai_base_url"`
	OpenAIModel      string `json:"openai_model"`
}

type row struct {
	githubCipher []byte
	openaiCipher []byte
	baseURL      string
	model        string
}

type updateRequest struct {
	GitHubToken       *string `json:"github_token"`
	OpenAIAPIKey      *string `json:"openai_api_key"`
	OpenAIBaseURL     *string `json:"openai_base_url"`
	OpenAIModel       *string `json:"openai_model"`
	ClearGitHubToken  bool    `json:"clear_github_token"`
	ClearOpenAIAPIKey bool    `json:"clear_openai_api_key"`
}

func (s *Service) Get(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	view, err := s.view(r.Context(), userID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	httputil.JSON(w, http.StatusOK, view)
}

func (s *Service) Update(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	var req updateRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Invalid JSON body")
		return
	}
	current, err := s.load(r.Context(), userID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if req.ClearGitHubToken {
		current.githubCipher = nil
	} else if token := trimPtr(req.GitHubToken); token != "" {
		enc, encErr := crypto.Encrypt(s.encKey, []byte(token))
		if encErr != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		current.githubCipher = enc
	}
	if req.ClearOpenAIAPIKey {
		current.openaiCipher = nil
	} else if key := trimPtr(req.OpenAIAPIKey); key != "" {
		enc, encErr := crypto.Encrypt(s.encKey, []byte(key))
		if encErr != nil {
			httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
			return
		}
		current.openaiCipher = enc
	}
	if req.OpenAIBaseURL != nil {
		current.baseURL = strings.TrimSpace(*req.OpenAIBaseURL)
	}
	if req.OpenAIModel != nil {
		current.model = strings.TrimSpace(*req.OpenAIModel)
	}
	if _, err := s.pool.Exec(r.Context(), `
		INSERT INTO user_settings (user_id, github_token_ciphertext, openai_api_key_ciphertext, openai_base_url, openai_model, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (user_id) DO UPDATE SET
			github_token_ciphertext = EXCLUDED.github_token_ciphertext,
			openai_api_key_ciphertext = EXCLUDED.openai_api_key_ciphertext,
			openai_base_url = EXCLUDED.openai_base_url,
			openai_model = EXCLUDED.openai_model,
			updated_at = now()
	`, userID, nullBytes(current.githubCipher), nullBytes(current.openaiCipher), current.baseURL, current.model); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	view, err := s.view(r.Context(), userID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	httputil.JSON(w, http.StatusOK, view)
}

func (s *Service) GitHubToken(ctx context.Context, userID string) (string, error) {
	current, err := s.load(ctx, userID)
	if err != nil {
		return "", err
	}
	return s.decrypt(current.githubCipher)
}

func (s *Service) OpenAI(ctx context.Context, userID string) (key, baseURL, model string, err error) {
	current, err := s.load(ctx, userID)
	if err != nil {
		return "", "", "", err
	}
	key, err = s.decrypt(current.openaiCipher)
	if err != nil {
		return "", "", "", err
	}
	return key, current.baseURL, current.model, nil
}

func (s *Service) view(ctx context.Context, userID string) (View, error) {
	current, err := s.load(ctx, userID)
	if err != nil {
		return View{}, err
	}
	out := View{OpenAIBaseURL: current.baseURL, OpenAIModel: current.model}
	if github, err := s.decrypt(current.githubCipher); err != nil {
		return View{}, err
	} else if github != "" {
		out.GitHubTokenSet = true
		out.GitHubTokenHint = Hint(github)
	}
	if openai, err := s.decrypt(current.openaiCipher); err != nil {
		return View{}, err
	} else if openai != "" {
		out.OpenAIAPIKeySet = true
		out.OpenAIAPIKeyHint = Hint(openai)
	}
	return out, nil
}

func (s *Service) load(ctx context.Context, userID string) (row, error) {
	var current row
	err := s.pool.QueryRow(ctx, `
		SELECT github_token_ciphertext, openai_api_key_ciphertext, openai_base_url, openai_model
		FROM user_settings WHERE user_id=$1
	`, userID).Scan(&current.githubCipher, &current.openaiCipher, &current.baseURL, &current.model)
	if errors.Is(err, pgx.ErrNoRows) {
		return row{}, nil
	}
	return current, err
}

func (s *Service) decrypt(ciphertext []byte) (string, error) {
	if len(ciphertext) == 0 {
		return "", nil
	}
	plain, err := crypto.Decrypt(s.encKey, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func Hint(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	if len(secret) <= 4 {
		return "••••"
	}
	return "••••" + secret[len(secret)-4:]
}

func trimPtr(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

func nullBytes(v []byte) any {
	if len(v) == 0 {
		return nil
	}
	return v
}
