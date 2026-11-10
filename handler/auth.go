package handler

import (
	"encoding/json"
	"net/http"

	"github.com/kaiizer777/go-auth/auth"
	"github.com/kaiizer777/go-auth/db"
	"github.com/kaiizer777/go-auth/errors"
)

// AuthHandler handles HTTP requests for user authentication and lifecycle operations.
type AuthHandler struct {
	svc auth.Service
}

// NewAuthHandler constructs a new AuthHandler.
func NewAuthHandler(svc auth.Service) *AuthHandler {
	return &AuthHandler{svc: svc}
}

func decodeJSON[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var target T
	if r.Body == nil {
		errors.WriteJSON(w, errors.New(errors.CodeValidationError, "invalid request body", nil))
		return target, false
	}
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&target); err != nil {
		errors.WriteJSON(w, errors.New(errors.CodeValidationError, "invalid request body", err))
		return target, false
	}
	return target, true
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// Signup handles user registration.
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[db.SignupRequest](w, r)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	if _, _, err := h.svc.Signup(r.Context(), req); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, db.MessageResponse{
		Message: "if this email is new, a verification link has been sent",
	})
}

// Login handles user authentication and credential verification.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[db.LoginRequest](w, r)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	user, err := h.svc.Login(r.Context(), req)
	if err != nil {
		errors.WriteJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, db.LoginResponse{
		UserID: user.ID,
	})
}

// Logout terminates the current session.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// VerifyEmail verifies a user's email with a single-use token.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[db.VerifyEmailRequest](w, r)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	if err := h.svc.VerifyEmail(r.Context(), req); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, db.MessageResponse{
		Message: "email verified",
	})
}

// RequestPasswordReset initiates a password reset flow.
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[db.PasswordResetRequest](w, r)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	if _, err := h.svc.RequestPasswordReset(r.Context(), req); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, db.MessageResponse{
		Message: "if an account with that email exists, a password reset link has been sent",
	})
}

// ResetPassword completes a password reset using a single-use token.
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[db.PasswordResetConfirmRequest](w, r)
	if !ok {
		return
	}
	if err := req.Validate(); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	if err := h.svc.ResetPassword(r.Context(), req); err != nil {
		errors.WriteJSON(w, err)
		return
	}
	writeJSON(w, http.StatusOK, db.MessageResponse{
		Message: "password reset successful",
	})
}
