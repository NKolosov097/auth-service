package domain

import (
	"time"
)

type Provider string

const (
	ProviderEmail    Provider = "email"
	ProviderGoogle   Provider = "google"
	ProviderTelegram Provider = "telegram"
)

type User struct {
	ID             int64
	Email          string
	PasswordHash   string
	Provider       Provider
	ProviderID     string // google sub / telegram id
	EmailConfirmed bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Session struct {
	ID           int64
	UserID       int64
	RefreshToken string
	UserAgent    string
	IP           string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

type ResetToken struct {
	UserID    int64
	Token     string
	ExpiresAt time.Time
}

type ChangeEmailToken struct {
	UserID    int64
	NewEmail  string
	Token     string
	ExpiresAt time.Time
}
