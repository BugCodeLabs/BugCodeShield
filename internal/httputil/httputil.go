package httputil

import (
	"encoding/json"
	"errors"
	"net/http"
)

type ErrorBody struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrValidation   = errors.New("validation")
)

func JSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func Error(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, ErrorBody{Error: message, Code: code})
}

func Decode(r *http.Request, dest any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dest)
}

func WriteAppError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized):
		Error(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
	case errors.Is(err, ErrForbidden):
		Error(w, http.StatusForbidden, "forbidden", "You do not have access to this resource")
	case errors.Is(err, ErrNotFound):
		Error(w, http.StatusNotFound, "not_found", "Resource not found")
	case errors.Is(err, ErrConflict):
		Error(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, ErrValidation):
		Error(w, http.StatusBadRequest, "validation", err.Error())
	default:
		Error(w, http.StatusInternalServerError, "internal", "Internal server error")
	}
}
