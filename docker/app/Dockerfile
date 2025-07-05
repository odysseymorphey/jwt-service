FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY ./go.mod ./
RUN go mod download

COPY . .

RUN go mod tidy &&\
    go build -o build/server cmd/main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/build/server .
COPY .env .

CMD ["/app/server"]