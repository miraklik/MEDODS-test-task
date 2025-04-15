FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod tidy

COPY . .

RUN go build -o ./cmd

FROM alpine:latest

RUN RUN apk --no-cache add ca-certificates

COPY --from=builder /app/auth-app /auth-app

EXPOSE 8080 

ENTRYPOINT [ "/cmd" ]