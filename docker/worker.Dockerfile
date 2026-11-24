FROM golang:1.23-alpine AS build

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/worker ./cmd/worker

FROM alpine:3.21

RUN apk add --no-cache ca-certificates git docker-cli \
    && mkdir -p /var/lib/bugcodeshield/scans

COPY --from=build /out/worker /usr/local/bin/worker

WORKDIR /var/lib/bugcodeshield
ENTRYPOINT ["/usr/local/bin/worker"]
