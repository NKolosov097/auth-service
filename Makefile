.PHONY: run build lint test migrate

run:
	go run ./cmd/auth

build:
	go build -o bin/auth ./cmd/auth

lint:
	golangci-lint run ./...

test:
	go test -race -count=1 ./...

migrate:
	psql "$$DATABASE_URL" -f migrations/001_init.sql
