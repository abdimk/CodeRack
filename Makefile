build:
	@go build -o bin/coderack cmd/main.go

run:build
	@./bin/coderack
	