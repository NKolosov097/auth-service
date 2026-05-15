package handler

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/NKolosov097/auth/internal/domain"
	"github.com/NKolosov097/auth/internal/service"
)

// POST /v1/auth/register
func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validateEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "invalid email address")
		return
	}
	if len(req.Password) < 12 || len(req.Password) > 72 {
		writeError(w, http.StatusBadRequest, "password must be 12–72 characters")
		return
	}
	pair, err := h.auth.RegisterEmail(r.Context(), req.Email, req.Password, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, pair)
}

// POST /v1/auth/login
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	pair, err := h.auth.LoginEmail(r.Context(), service.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		UserAgent: r.UserAgent(),
		IP:        r.RemoteAddr,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

// POST /v1/auth/refresh
func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &req); err != nil || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token required")
		return
	}
	pair, err := h.auth.RefreshTokens(r.Context(), req.RefreshToken, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

// POST /v1/auth/logout
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &req); err != nil || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token required")
		return
	}
	if err := h.auth.Logout(r.Context(), req.RefreshToken); err != nil {
		h.log.Error("logout failed", "err", err)
		writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /v1/auth/forgot-password
func (h *Handler) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// always 200 to avoid email enumeration
	_ = h.auth.ForgotPassword(r.Context(), req.Email)
	writeJSON(w, http.StatusOK, map[string]string{"message": "if the email exists you will receive a reset link"})
}

// POST /v1/auth/reset-password
func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Token == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "token and password are required")
		return
	}
	if err := h.auth.ResetPassword(r.Context(), req.Token, req.Password); err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
}

// POST /v1/auth/change-password  (auth required)
func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.auth.ChangePassword(r.Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "password changed"})
}

// POST /v1/auth/change-email  (auth required)
func (h *Handler) requestEmailChange(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req struct {
		NewEmail string `json:"new_email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !validateEmail(req.NewEmail) {
		writeError(w, http.StatusBadRequest, "invalid email address")
		return
	}
	if err := h.auth.RequestEmailChange(r.Context(), userID, req.NewEmail); err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "confirmation link sent to new email"})
}

// GET /v1/auth/confirm-email-change?token=...
func (h *Handler) confirmEmailChange(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if tok == "" {
		writeError(w, http.StatusBadRequest, "token required")
		return
	}
	if err := h.auth.ConfirmEmailChange(r.Context(), tok); err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "email changed"})
}

// --- Google OAuth2 -----------------------------------------------------------

const oauthStateCookie = "oauth_state"

// GET /v1/auth/google
func (h *Handler) googleLogin(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate state")
		return
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    state,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/v1/auth/google/callback",
		MaxAge:   600,
	})
	http.Redirect(w, r, h.googleOAuth.AuthCodeURL(state), http.StatusSeeOther)
}

// GET /v1/auth/google/callback
func (h *Handler) googleCallback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(oauthStateCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.URL.Query().Get("state"))) != 1 {
		writeError(w, http.StatusBadRequest, "invalid oauth state")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oauthStateCookie, MaxAge: -1, Path: "/v1/auth/google/callback"})

	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing code")
		return
	}
	t, err := h.googleOAuth.Exchange(r.Context(), code)
	if err != nil {
		writeError(w, http.StatusBadRequest, "oauth exchange failed")
		return
	}
	info, err := fetchGoogleUserInfo(r.Context(), t.AccessToken)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch user info")
		return
	}
	pair, err := h.auth.LoginOAuth(r.Context(), service.OAuthInput{
		Provider:   domain.ProviderGoogle,
		ProviderID: info.Sub,
		Email:      info.Email,
		UserAgent:  r.UserAgent(),
		IP:         r.RemoteAddr,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

type googleUserInfo struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
}

func fetchGoogleUserInfo(ctx context.Context, accessToken string) (*googleUserInfo, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://openidconnect.googleapis.com/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch google userinfo: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var info googleUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("decode google userinfo: %w", err)
	}
	return &info, nil
}

// --- Telegram Login Widget ---------------------------------------------------
// https://core.telegram.org/widgets/login

// POST /v1/auth/telegram
// Body: the fields sent by the Telegram Login Widget
func (h *Handler) telegramLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form data")
		return
	}
	params := map[string]string{
		"id":         r.FormValue("id"),
		"first_name": r.FormValue("first_name"),
		"last_name":  r.FormValue("last_name"),
		"username":   r.FormValue("username"),
		"photo_url":  r.FormValue("photo_url"),
		"auth_date":  r.FormValue("auth_date"),
	}
	hash := r.FormValue("hash")
	if !verifyTelegramAuth(h.telegramBot, params, hash) {
		writeError(w, http.StatusUnauthorized, "telegram auth verification failed")
		return
	}
	authDate, _ := strconv.ParseInt(params["auth_date"], 10, 64)
	if time.Now().Unix()-authDate > 60 {
		writeError(w, http.StatusUnauthorized, "telegram auth expired")
		return
	}
	pair, err := h.auth.LoginOAuth(r.Context(), service.OAuthInput{
		Provider:   domain.ProviderTelegram,
		ProviderID: params["id"],
		Email:      "", // Telegram doesn't provide email
		UserAgent:  r.UserAgent(),
		IP:         r.RemoteAddr,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

// verifyTelegramAuth validates the HMAC from the Telegram Login Widget.
func verifyTelegramAuth(botToken string, params map[string]string, hash string) bool {
	// build sorted key=value data-check string
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+params[k]) // raw values per Telegram spec
	}
	dataCheckString := strings.Join(parts, "\n")

	// secret key = SHA-256 of bot token
	h256 := sha256.New()
	h256.Write([]byte(botToken))
	secretKey := h256.Sum(nil)

	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(dataCheckString))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(hash))
}

// validateEmail returns true if s is a well-formed email address with no
// control characters (guards against SMTP header injection).
func validateEmail(s string) bool {
	if len(s) == 0 || len(s) > 254 || strings.ContainsAny(s, "\r\n") {
		return false
	}
	_, err := mail.ParseAddress(s)
	return err == nil
}

// handleServiceError maps domain errors to HTTP status codes.
func (h *Handler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid credentials")
	case errors.Is(err, domain.ErrAlreadyExists):
		writeError(w, http.StatusConflict, "already exists")
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, domain.ErrTokenExpired):
		writeError(w, http.StatusUnauthorized, "token expired")
	case errors.Is(err, domain.ErrTokenInvalid):
		writeError(w, http.StatusUnauthorized, "token invalid")
	case errors.Is(err, domain.ErrProviderMismatch):
		writeError(w, http.StatusConflict, "account registered with different provider")
	default:
		h.log.Error("internal error", "err", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
	}
}
