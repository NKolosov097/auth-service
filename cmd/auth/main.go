package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NKolosov097/auth/internal/config"
	"github.com/NKolosov097/auth/internal/handler"
	"github.com/NKolosov097/auth/internal/mailer"
	"github.com/NKolosov097/auth/internal/repository/postgres"
	"github.com/NKolosov097/auth/internal/service"
	"github.com/NKolosov097/auth/internal/token"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(log); err != nil {
		log.Error("startup failed", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Database
	poolCfg, err := pgxpool.ParseConfig(cfg.DB.DSN)
	if err != nil {
		return fmt.Errorf("parse db dsn: %w", err)
	}
	poolCfg.MaxConns = int32(cfg.DB.MaxOpenConns)

	db, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		return fmt.Errorf("connect to db: %w", err)
	}
	defer db.Close()

	if err := db.Ping(context.Background()); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}
	log.Info("database connected")

	// Repos
	userRepo := postgres.NewUserRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)
	tokenRepo := postgres.NewTokenRepo(db)

	// JWT
	jwtMgr := token.NewManager(
		cfg.JWT.AccessSecret, cfg.JWT.RefreshSecret,
		cfg.JWT.AccessTTL, cfg.JWT.RefreshTTL,
	)

	// Mailer
	ml := mailer.New(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.Username, cfg.SMTP.Password, cfg.SMTP.From, cfg.SMTP.ImplicitTLS)

	appURL := os.Getenv("APP_URL")
	if appURL == "" {
		appURL = "http://localhost:3000"
	}

	// Service
	authSvc := service.NewAuth(userRepo, sessionRepo, tokenRepo, jwtMgr, ml, appURL, log)

	// Handler
	h := handler.New(
		authSvc, jwtMgr,
		cfg.Google.ClientID, cfg.Google.ClientSecret, cfg.Google.RedirectURL,
		cfg.Telegram.BotToken,
		log,
	)

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           h.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 14, // 16 KiB
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info("http server starting", "addr", cfg.HTTP.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server error", "err", err)
		}
	}()

	<-quit
	log.Info("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()
	return srv.Shutdown(ctx)
}
