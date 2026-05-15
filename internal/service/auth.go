package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/NKolosov097/auth/internal/domain"
	"github.com/NKolosov097/auth/internal/token"
	"golang.org/x/crypto/bcrypt"
)

// Interfaces consumed by the service — defined here (consumer side).

type UserRepository interface {
	Create(ctx context.Context, u *domain.User) error
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id int64) (*domain.User, error)
	GetByProviderID(ctx context.Context, provider domain.Provider, providerID string) (*domain.User, error)
	UpdatePassword(ctx context.Context, userID int64, hash string) error
	UpdateEmail(ctx context.Context, userID int64, email string) error
	ConfirmEmail(ctx context.Context, userID int64) error
}

type SessionRepository interface {
	Create(ctx context.Context, s *domain.Session) error
	GetByToken(ctx context.Context, token string) (*domain.Session, error)
	Delete(ctx context.Context, token string) error
	DeleteAllForUser(ctx context.Context, userID int64) error
}

type TokenRepository interface {
	SaveResetToken(ctx context.Context, t *domain.ResetToken) error
	GetResetToken(ctx context.Context, token string) (*domain.ResetToken, error)
	DeleteResetToken(ctx context.Context, token string) error
	SaveChangeEmailToken(ctx context.Context, t *domain.ChangeEmailToken) error
	GetChangeEmailToken(ctx context.Context, token string) (*domain.ChangeEmailToken, error)
	DeleteChangeEmailToken(ctx context.Context, token string) error
}

type Mailer interface {
	SendPasswordReset(to, token, appURL string) error
	SendEmailChange(to, token, appURL string) error
}

// DTO ------------------------------------------------------------------------

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type LoginInput struct {
	Email    string
	Password string
	UserAgent string
	IP        string
}

type OAuthInput struct {
	Provider   domain.Provider
	ProviderID string
	Email      string
	UserAgent  string
	IP         string
}

// Auth service ---------------------------------------------------------------

const bcryptCost = 12

type Auth struct {
	users     UserRepository
	sessions  SessionRepository
	tokens    TokenRepository
	jwt       *token.Manager
	mailer    Mailer
	appURL    string
	log       *slog.Logger
	dummyHash string // pre-computed hash for constant-time login when user not found
}

func NewAuth(
	users UserRepository,
	sessions SessionRepository,
	tokens TokenRepository,
	jwt *token.Manager,
	mailer Mailer,
	appURL string,
	log *slog.Logger,
) *Auth {
	dummy, _ := bcrypt.GenerateFromPassword([]byte("dummy-timing-constant"), bcryptCost)
	return &Auth{
		users:     users,
		sessions:  sessions,
		tokens:    tokens,
		jwt:       jwt,
		mailer:    mailer,
		appURL:    appURL,
		log:       log,
		dummyHash: string(dummy),
	}
}

// LoginEmail authenticates a user via email + password.
func (a *Auth) LoginEmail(ctx context.Context, in LoginInput) (*TokenPair, error) {
	u, err := a.users.GetByEmail(ctx, in.Email)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			// always run bcrypt to equalise response time and prevent user enumeration
			_ = bcrypt.CompareHashAndPassword([]byte(a.dummyHash), []byte(in.Password))
			a.log.Warn("login failed: user not found", "email", in.Email, "ip", in.IP)
			return nil, domain.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("login email: %w", err)
	}
	if u.Provider != domain.ProviderEmail {
		a.log.Warn("login failed: provider mismatch", "email", in.Email, "provider", u.Provider, "ip", in.IP)
		return nil, domain.ErrProviderMismatch
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)); err != nil {
		a.log.Warn("login failed: wrong password", "email", in.Email, "ip", in.IP)
		return nil, domain.ErrInvalidCredentials
	}
	pair, err := a.issueTokenPair(ctx, u, in.UserAgent, in.IP)
	if err != nil {
		return nil, err
	}
	a.log.Info("user logged in", "user_id", u.ID, "email", u.Email, "ip", in.IP)
	return pair, nil
}

// RegisterEmail creates a new email+password user.
func (a *Auth) RegisterEmail(ctx context.Context, email, password, userAgent, ip string) (*TokenPair, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	u := &domain.User{
		Email:          email,
		PasswordHash:   string(hash),
		Provider:       domain.ProviderEmail,
		EmailConfirmed: false,
	}
	if err := a.users.Create(ctx, u); err != nil {
		return nil, fmt.Errorf("register email: %w", err)
	}
	pair, err := a.issueTokenPair(ctx, u, userAgent, ip)
	if err != nil {
		return nil, err
	}
	a.log.Info("user registered", "user_id", u.ID, "email", u.Email, "ip", ip)
	return pair, nil
}

// LoginOAuth upserts an OAuth user and returns a token pair.
func (a *Auth) LoginOAuth(ctx context.Context, in OAuthInput) (*TokenPair, error) {
	u, err := a.users.GetByProviderID(ctx, in.Provider, in.ProviderID)
	if errors.Is(err, domain.ErrNotFound) {
		// first login — create the user
		u = &domain.User{
			Email:          in.Email,
			Provider:       in.Provider,
			ProviderID:     in.ProviderID,
			EmailConfirmed: true,
		}
		if err := a.users.Create(ctx, u); err != nil && !errors.Is(err, domain.ErrAlreadyExists) {
			return nil, fmt.Errorf("create oauth user: %w", err)
		}
		if errors.Is(err, domain.ErrAlreadyExists) {
			a.log.Warn("oauth login failed: email taken by another provider", "email", in.Email, "provider", in.Provider, "ip", in.IP)
			return nil, domain.ErrProviderMismatch
		}
		a.log.Info("oauth user created", "user_id", u.ID, "email", u.Email, "provider", in.Provider, "ip", in.IP)
	} else if err != nil {
		return nil, fmt.Errorf("get oauth user: %w", err)
	}
	pair, err := a.issueTokenPair(ctx, u, in.UserAgent, in.IP)
	if err != nil {
		return nil, err
	}
	a.log.Info("oauth user logged in", "user_id", u.ID, "provider", in.Provider, "ip", in.IP)
	return pair, nil
}

// RefreshTokens rotates the refresh token.
func (a *Auth) RefreshTokens(ctx context.Context, rawRefresh, userAgent, ip string) (*TokenPair, error) {
	claims, err := a.jwt.ParseRefreshToken(rawRefresh)
	if err != nil {
		a.log.Warn("token refresh failed: invalid token", "ip", ip)
		return nil, domain.ErrTokenInvalid
	}
	sess, err := a.sessions.GetByToken(ctx, rawRefresh)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			a.log.Warn("token refresh failed: session not found", "user_id", claims.UserID, "ip", ip)
			return nil, domain.ErrTokenInvalid
		}
		return nil, fmt.Errorf("refresh tokens: %w", err)
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = a.sessions.Delete(ctx, rawRefresh)
		a.log.Warn("token refresh failed: session expired", "user_id", claims.UserID, "ip", ip)
		return nil, domain.ErrTokenExpired
	}
	// rotate: delete old, issue new
	if err := a.sessions.Delete(ctx, rawRefresh); err != nil {
		return nil, fmt.Errorf("delete old session: %w", err)
	}
	u := &domain.User{ID: claims.UserID, Email: claims.Email}
	pair, err := a.issueTokenPair(ctx, u, userAgent, ip)
	if err != nil {
		return nil, err
	}
	a.log.Info("tokens refreshed", "user_id", u.ID, "ip", ip)
	return pair, nil
}

// Logout invalidates a refresh token.
func (a *Auth) Logout(ctx context.Context, rawRefresh string) error {
	if err := a.sessions.Delete(ctx, rawRefresh); err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	a.log.Info("user logged out")
	return nil
}

// ForgotPassword sends a password-reset email.
func (a *Auth) ForgotPassword(ctx context.Context, email string) error {
	u, err := a.users.GetByEmail(ctx, email)
	if err != nil {
		// don't leak whether the address exists
		return nil
	}
	if u.Provider != domain.ProviderEmail {
		return nil
	}
	tok, err := randomHex(32)
	if err != nil {
		return fmt.Errorf("generate reset token: %w", err)
	}
	rt := &domain.ResetToken{
		UserID:    u.ID,
		Token:     tok,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := a.tokens.SaveResetToken(ctx, rt); err != nil {
		return fmt.Errorf("save reset token: %w", err)
	}
	// fire-and-forget is intentional — don't block the HTTP response
	go func() {
		if err := a.mailer.SendPasswordReset(email, tok, a.appURL); err != nil {
			a.log.Error("send password reset email", "email", email, "err", err)
		}
	}()
	a.log.Info("password reset requested", "user_id", u.ID)
	return nil
}

// ResetPassword applies a password-reset token.
func (a *Auth) ResetPassword(ctx context.Context, resetToken, newPassword string) error {
	rt, err := a.tokens.GetResetToken(ctx, resetToken)
	if err != nil {
		return err // ErrNotFound or ErrTokenExpired
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := a.users.UpdatePassword(ctx, rt.UserID, string(hash)); err != nil {
		return fmt.Errorf("reset password: %w", err)
	}
	_ = a.tokens.DeleteResetToken(ctx, resetToken)
	_ = a.sessions.DeleteAllForUser(ctx, rt.UserID)
	a.log.Info("password reset completed", "user_id", rt.UserID)
	return nil
}

// ChangePassword changes a logged-in user's password.
func (a *Auth) ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error {
	u, err := a.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	if u.Provider != domain.ProviderEmail {
		return domain.ErrProviderMismatch
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(oldPassword)); err != nil {
		return domain.ErrInvalidCredentials
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := a.users.UpdatePassword(ctx, userID, string(hash)); err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	_ = a.sessions.DeleteAllForUser(ctx, userID)
	a.log.Info("password changed", "user_id", userID)
	return nil
}

// RequestEmailChange sends a confirmation link to the new address.
func (a *Auth) RequestEmailChange(ctx context.Context, userID int64, newEmail string) error {
	tok, err := randomHex(32)
	if err != nil {
		return fmt.Errorf("generate change-email token: %w", err)
	}
	ct := &domain.ChangeEmailToken{
		UserID:    userID,
		NewEmail:  newEmail,
		Token:     tok,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := a.tokens.SaveChangeEmailToken(ctx, ct); err != nil {
		return fmt.Errorf("save change-email token: %w", err)
	}
	go func() {
		if err := a.mailer.SendEmailChange(newEmail, tok, a.appURL); err != nil {
			a.log.Error("send email change confirmation", "user_id", userID, "err", err)
		}
	}()
	a.log.Info("email change requested", "user_id", userID)
	return nil
}

// ConfirmEmailChange applies a change-email token.
func (a *Auth) ConfirmEmailChange(ctx context.Context, changeToken string) error {
	ct, err := a.tokens.GetChangeEmailToken(ctx, changeToken)
	if err != nil {
		return err
	}
	if err := a.users.UpdateEmail(ctx, ct.UserID, ct.NewEmail); err != nil {
		return fmt.Errorf("confirm email change: %w", err)
	}
	_ = a.tokens.DeleteChangeEmailToken(ctx, changeToken)
	_ = a.sessions.DeleteAllForUser(ctx, ct.UserID)
	a.log.Info("email change confirmed", "user_id", ct.UserID, "new_email", ct.NewEmail)
	return nil
}

// issueTokenPair creates an access+refresh pair and persists the session.
func (a *Auth) issueTokenPair(ctx context.Context, u *domain.User, userAgent, ip string) (*TokenPair, error) {
	access, err := a.jwt.NewAccessToken(u.ID, u.Email)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}
	refresh, err := a.jwt.NewRefreshToken(u.ID, u.Email)
	if err != nil {
		return nil, fmt.Errorf("issue refresh token: %w", err)
	}
	sess := &domain.Session{
		UserID:       u.ID,
		RefreshToken: refresh,
		UserAgent:    userAgent,
		IP:           ip,
		ExpiresAt:    time.Now().Add(a.jwt.RefreshTTL()),
	}
	if err := a.sessions.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return &TokenPair{AccessToken: access, RefreshToken: refresh}, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
