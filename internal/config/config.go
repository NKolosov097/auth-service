package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTP     HTTP
	DB       DB
	JWT      JWT
	Google   Google
	Telegram Telegram
	SMTP     SMTP
}

type HTTP struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

type DB struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type JWT struct {
	AccessSecret  string
	RefreshSecret string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
}

type Google struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type Telegram struct {
	BotToken string
}

type SMTP struct {
	Host        string
	Port        int
	Username    string
	Password    string
	From        string
	ImplicitTLS bool // true = port 465 implicit TLS; false = STARTTLS (port 587)
}

func Load() (*Config, error) {
	smtpPort, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	if err != nil {
		return nil, fmt.Errorf("invalid SMTP_PORT: %w", err)
	}

	return &Config{
		HTTP: HTTP{
			Addr:            getEnv("HTTP_ADDR", ":8080"),
			ReadTimeout:     10 * time.Second,
			WriteTimeout:    10 * time.Second,
			ShutdownTimeout: 15 * time.Second,
		},
		DB: DB{
			DSN:             mustEnv("DATABASE_URL"),
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		JWT: JWT{
			AccessSecret:  mustEnvSecret("JWT_ACCESS_SECRET"),
			RefreshSecret: mustEnvSecret("JWT_REFRESH_SECRET"),
			AccessTTL:     15 * time.Minute,
			RefreshTTL:    30 * 24 * time.Hour,
		},
		Google: Google{
			ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
			ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
			RedirectURL:  getEnv("GOOGLE_REDIRECT_URL", "http://localhost:8080/v1/auth/google/callback"),
		},
		Telegram: Telegram{
			BotToken: getEnv("TELEGRAM_BOT_TOKEN", ""),
		},
		SMTP: SMTP{
			Host:        getEnv("SMTP_HOST", "smtp.gmail.com"),
			Port:        smtpPort,
			Username:    getEnv("SMTP_USERNAME", ""),
			Password:    getEnv("SMTP_PASSWORD", ""),
			From:        getEnv("SMTP_FROM", "noreply@example.com"),
			ImplicitTLS: getEnvBool("SMTP_IMPLICIT_TLS", false),
		},
	}, nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		panic(fmt.Sprintf("required env var %q is not set", key))
	}
	return v
}

func mustEnvSecret(key string) string {
	v := mustEnv(key)
	if len(v) < 32 {
		panic(fmt.Sprintf("env var %q must be at least 32 characters", key))
	}
	return v
}

func getEnvBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
