package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/NKolosov097/auth/internal/service"
	"github.com/NKolosov097/auth/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/time/rate"
)

type AuthService interface {
	RegisterEmail(ctx context.Context, email, password, userAgent, ip string) (*service.TokenPair, error)
	LoginEmail(ctx context.Context, in service.LoginInput) (*service.TokenPair, error)
	LoginOAuth(ctx context.Context, in service.OAuthInput) (*service.TokenPair, error)
	RefreshTokens(ctx context.Context, rawRefresh, userAgent, ip string) (*service.TokenPair, error)
	Logout(ctx context.Context, rawRefresh string) error
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, resetToken, newPassword string) error
	ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error
	RequestEmailChange(ctx context.Context, userID int64, newEmail string) error
	ConfirmEmailChange(ctx context.Context, changeToken string) error
}

type Handler struct {
	auth          AuthService
	jwt           *token.Manager
	googleOAuth   *oauth2.Config
	telegramBot   string
	log           *slog.Logger
	globalLimiter *rateLimiter
	authLimiter   *rateLimiter
}

func New(
	auth AuthService,
	jwt *token.Manager,
	googleClientID, googleClientSecret, googleRedirectURL string,
	telegramBotToken string,
	log *slog.Logger,
) *Handler {
	return &Handler{
		auth: auth,
		jwt:  jwt,
		googleOAuth: &oauth2.Config{
			ClientID:     googleClientID,
			ClientSecret: googleClientSecret,
			RedirectURL:  googleRedirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
		telegramBot:   telegramBotToken,
		log:           log,
		globalLimiter: newRateLimiter(rate.Every(time.Minute/100), 20), // 100 req/min burst 20
		authLimiter:   newRateLimiter(rate.Every(time.Minute/10), 5),   // 10 req/min burst 5
	}
}

func (h *Handler) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(secureHeaders)
	r.Use(limitBody)
	r.Use(h.globalLimiter.middleware)
	r.Use(h.requestLogger)

	r.Route("/v1/auth", func(r chi.Router) {
		// rate-limited public endpoints
		r.Group(func(r chi.Router) {
			r.Use(h.authLimiter.middleware)
			r.Post("/register", h.register)
			r.Post("/login", h.login)
			r.Post("/refresh", h.refresh)
			r.Post("/forgot-password", h.forgotPassword)
			r.Post("/reset-password", h.resetPassword)
			r.Post("/telegram", h.telegramLogin)
		})

		r.Get("/google", h.googleLogin)
		r.Get("/google/callback", h.googleCallback)
		r.Get("/confirm-email-change", h.confirmEmailChange)

		// protected
		r.Group(func(r chi.Router) {
			r.Use(h.authMiddleware)
			r.Post("/logout", h.logout)
			r.Post("/change-password", h.changePassword)
			r.Post("/change-email", h.requestEmailChange)
		})
	})
	return r
}

// helpers --------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
