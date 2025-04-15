migrate-users: 
	migrate create -ext sql -dir db/migrations users

migrate-token:
	migrate create -ext sql -dir db/migrations refresh_tokens

run:
	go run cmd/main.go

.PHONY: run, migrate-users, migrate-token