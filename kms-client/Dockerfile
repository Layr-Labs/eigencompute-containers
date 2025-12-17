FROM golang:1.25 AS builder
WORKDIR /src

# Cache go modules between builds
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -trimpath \
        -buildvcs=false \
        -ldflags="-s -w -extldflags '-static'" \
        -o /out/kms-client \
        ./cmd/kms-client

FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/kms-client /eigen/bin/kms-client
ENTRYPOINT ["/eigen/bin/kms-client"]

