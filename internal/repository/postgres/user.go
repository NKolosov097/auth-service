package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/NKolosov097/auth/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// tokenHash returns sha256(t) so raw tokens are never persisted.
func tokenHash(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

type UserRepo struct {
	db *pgxpool.Pool
}

func NewUserRepo(db *pgxpool.Pool) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(ctx context.Context, u *domain.User) error {
	q := `INSERT INTO users (email, password_hash, provider, provider_id, email_confirmed)
	      VALUES ($1, $2, $3, $4, $5)
	      RETURNING id, created_at, updated_at`
	err := r.db.QueryRow(ctx, q,
		u.Email, u.PasswordHash, u.Provider, u.ProviderID, u.EmailConfirmed,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrAlreadyExists
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.getBy(ctx, "email", email)
}

func (r *UserRepo) GetByID(ctx context.Context, id int64) (*domain.User, error) {
	return r.getBy(ctx, "id", id)
}

func (r *UserRepo) GetByProviderID(ctx context.Context, provider domain.Provider, providerID string) (*domain.User, error) {
	q := `SELECT id, email, password_hash, provider, provider_id, email_confirmed, created_at, updated_at
	      FROM users WHERE provider = $1 AND provider_id = $2`
	u := &domain.User{}
	err := r.db.QueryRow(ctx, q, provider, providerID).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Provider, &u.ProviderID,
		&u.EmailConfirmed, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get user by provider: %w", err)
	}
	return u, nil
}

func (r *UserRepo) UpdatePassword(ctx context.Context, userID int64, hash string) error {
	q := `UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`
	ct, err := r.db.Exec(ctx, q, hash, userID)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *UserRepo) UpdateEmail(ctx context.Context, userID int64, email string) error {
	q := `UPDATE users SET email = $1, updated_at = now() WHERE id = $2`
	ct, err := r.db.Exec(ctx, q, email, userID)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrAlreadyExists
		}
		return fmt.Errorf("update email: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *UserRepo) ConfirmEmail(ctx context.Context, userID int64) error {
	q := `UPDATE users SET email_confirmed = true, updated_at = now() WHERE id = $1`
	_, err := r.db.Exec(ctx, q, userID)
	return err
}

func (r *UserRepo) getBy(ctx context.Context, col string, val any) (*domain.User, error) {
	q := fmt.Sprintf(`SELECT id, email, password_hash, provider, provider_id, email_confirmed, created_at, updated_at
	                   FROM users WHERE %s = $1`, col)
	u := &domain.User{}
	err := r.db.QueryRow(ctx, q, val).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Provider, &u.ProviderID,
		&u.EmailConfirmed, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get user by %s: %w", col, err)
	}
	return u, nil
}

// SessionRepo ----------------------------------------------------------------

type SessionRepo struct {
	db *pgxpool.Pool
}

func NewSessionRepo(db *pgxpool.Pool) *SessionRepo {
	return &SessionRepo{db: db}
}

func (r *SessionRepo) Create(ctx context.Context, s *domain.Session) error {
	q := `INSERT INTO sessions (user_id, refresh_token, user_agent, ip, expires_at)
	      VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`
	return r.db.QueryRow(ctx, q, s.UserID, tokenHash(s.RefreshToken), s.UserAgent, s.IP, s.ExpiresAt).
		Scan(&s.ID, &s.CreatedAt)
}

func (r *SessionRepo) GetByToken(ctx context.Context, token string) (*domain.Session, error) {
	q := `SELECT id, user_id, user_agent, ip, expires_at, created_at
	      FROM sessions WHERE refresh_token = $1`
	s := &domain.Session{}
	err := r.db.QueryRow(ctx, q, tokenHash(token)).Scan(
		&s.ID, &s.UserID, &s.UserAgent, &s.IP, &s.ExpiresAt, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	s.RefreshToken = token // return the raw token to the caller
	return s, nil
}

func (r *SessionRepo) Delete(ctx context.Context, token string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM sessions WHERE refresh_token = $1`, tokenHash(token))
	return err
}

func (r *SessionRepo) DeleteAllForUser(ctx context.Context, userID int64) error {
	_, err := r.db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

// TokenRepo (reset / change-email one-time tokens) ---------------------------

type TokenRepo struct {
	db *pgxpool.Pool
}

func NewTokenRepo(db *pgxpool.Pool) *TokenRepo {
	return &TokenRepo{db: db}
}

func (r *TokenRepo) SaveResetToken(ctx context.Context, t *domain.ResetToken) error {
	q := `INSERT INTO reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)
	      ON CONFLICT (user_id) DO UPDATE SET token = $2, expires_at = $3`
	_, err := r.db.Exec(ctx, q, t.UserID, t.Token, t.ExpiresAt)
	return err
}

func (r *TokenRepo) GetResetToken(ctx context.Context, token string) (*domain.ResetToken, error) {
	q := `SELECT user_id, token, expires_at FROM reset_tokens WHERE token = $1`
	rt := &domain.ResetToken{}
	err := r.db.QueryRow(ctx, q, token).Scan(&rt.UserID, &rt.Token, &rt.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get reset token: %w", err)
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, domain.ErrTokenExpired
	}
	return rt, nil
}

func (r *TokenRepo) DeleteResetToken(ctx context.Context, token string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM reset_tokens WHERE token = $1`, token)
	return err
}

func (r *TokenRepo) SaveChangeEmailToken(ctx context.Context, t *domain.ChangeEmailToken) error {
	q := `INSERT INTO change_email_tokens (user_id, new_email, token, expires_at) VALUES ($1, $2, $3, $4)
	      ON CONFLICT (user_id) DO UPDATE SET new_email = $2, token = $3, expires_at = $4`
	_, err := r.db.Exec(ctx, q, t.UserID, t.NewEmail, t.Token, t.ExpiresAt)
	return err
}

func (r *TokenRepo) GetChangeEmailToken(ctx context.Context, token string) (*domain.ChangeEmailToken, error) {
	q := `SELECT user_id, new_email, token, expires_at FROM change_email_tokens WHERE token = $1`
	ct := &domain.ChangeEmailToken{}
	err := r.db.QueryRow(ctx, q, token).Scan(&ct.UserID, &ct.NewEmail, &ct.Token, &ct.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get change-email token: %w", err)
	}
	if time.Now().After(ct.ExpiresAt) {
		return nil, domain.ErrTokenExpired
	}
	return ct, nil
}

func (r *TokenRepo) DeleteChangeEmailToken(ctx context.Context, token string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM change_email_tokens WHERE token = $1`, token)
	return err
}

// isUniqueViolation returns true for PostgreSQL unique-constraint errors (23505).
func isUniqueViolation(err error) bool {
	type pgErr interface{ SQLState() string }
	var pe pgErr
	if errors.As(err, &pe) {
		return pe.SQLState() == "23505"
	}
	return false
}
