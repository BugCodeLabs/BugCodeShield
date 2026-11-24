FROM golang:1.23-alpine AS build

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/api ./cmd/api

FROM alpine:3.21

RUN apk add --no-cache ca-certificates wget \
    && adduser -D -H -u 65532 app

COPY --from=build /out/api /usr/local/bin/api

USER app
EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/api"]
