package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"bugcode-shield/internal/httputil"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const userIDKey contextKey = "userID"

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Service struct {
	pool   *pgxpool.Pool
	secret []byte
	ttl    time.Duration
}

func New(pool *pgxpool.Pool, secret string, ttl time.Duration) *Service {
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	return &Service{pool: pool, secret: []byte(secret), ttl: ttl}
}

type registerRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

func (s *Service) Routes() http.Handler {
	r := http.NewServeMux()
	// chi is used at the parent; methods are registered there.
	return r
}

func (s *Service) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Invalid JSON body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	name := strings.TrimSpace(req.Name)
	if email == "" || !strings.Contains(email, "@") {
		httputil.Error(w, http.StatusBadRequest, "validation", "A valid email is required")
		return
	}
	if len(name) < 2 {
		httputil.Error(w, http.StatusBadRequest, "validation", "Name must be at least 2 characters")
		return
	}
	if len(req.Password) < 8 {
		httputil.Error(w, http.StatusBadRequest, "validation", "Password must be at least 8 characters")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}

	ctx := r.Context()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	defer tx.Rollback(ctx)

	var user User
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email, name, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id::text, email, name, created_at
	`, email, name, string(hash)).Scan(&user.ID, &user.Email, &user.Name, &user.CreatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			httputil.Error(w, http.StatusConflict, "conflict", "An account with that email already exists")
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}

	orgName := name + "'s workspace"
	slug := slugify(name) + "-" + user.ID[:8]
	var orgID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id::text
	`, orgName, slug).Scan(&orgID); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1, $2, 'owner')
	`, orgID, user.ID); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}

	token, err := s.sign(user.ID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	httputil.JSON(w, http.StatusCreated, tokenResponse{Token: token, User: user})
}

func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Invalid JSON body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	var user User
	var hash string
	err := s.pool.QueryRow(r.Context(), `
		SELECT id::text, email, name, created_at, password_hash FROM users WHERE email=$1
	`, email).Scan(&user.ID, &user.Email, &user.Name, &user.CreatedAt, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httputil.Error(w, http.StatusUnauthorized, "unauthorized", "Invalid email or password")
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized", "Invalid email or password")
		return
	}
	token, err := s.sign(user.ID)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	httputil.JSON(w, http.StatusOK, tokenResponse{Token: token, User: user})
}

func (s *Service) Me(w http.ResponseWriter, r *http.Request) {
	userID := UserID(r.Context())
	user, err := s.loadUser(r.Context(), userID)
	if err != nil {
		httputil.WriteAppError(w, httputil.ErrUnauthorized)
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (s *Service) UpdateMe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "validation", "Invalid JSON body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if len(name) < 2 {
		httputil.Error(w, http.StatusBadRequest, "validation", "Name must be at least 2 characters")
		return
	}
	userID := UserID(r.Context())
	var user User
	err := s.pool.QueryRow(r.Context(), `
		UPDATE users SET name=$1, updated_at=now() WHERE id=$2
		RETURNING id::text, email, name, created_at
	`, name, userID).Scan(&user.ID, &user.Email, &user.Name, &user.CreatedAt)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "internal", "Internal server error")
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (s *Service) loadUser(ctx context.Context, userID string) (User, error) {
	var user User
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, email, name, created_at FROM users WHERE id=$1
	`, userID).Scan(&user.ID, &user.Email, &user.Name, &user.CreatedAt)
	return user, err
}

func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			httputil.WriteAppError(w, httputil.ErrUnauthorized)
			return
		}
		userID, err := s.parse(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			httputil.WriteAppError(w, httputil.ErrUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), userIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserID(ctx context.Context) string {
	v, _ := ctx.Value(userIDKey).(string)
	return v
}

func (s *Service) sign(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(s.ttl).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

func (s *Service) parse(token string) (string, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.secret, nil
	})
	if err != nil || !parsed.Valid {
		return "", httputil.ErrUnauthorized
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", httputil.ErrUnauthorized
	}
	sub, _ := claims["sub"].(string)
	if _, err := uuid.Parse(sub); err != nil {
		return "", httputil.ErrUnauthorized
	}
	return sub, nil
}

func slugify(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r == ' ' || r == '_' {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "workspace"
	}
	return out
}
