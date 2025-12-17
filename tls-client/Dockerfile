FROM golang:1.25 AS builder
WORKDIR /src

# Download modules and build the binary.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -extldflags '-static'" \
    -o /out/tls-client \
    ./cmd/tls-client

FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/tls-client /eigen/bin/tls-client
ENTRYPOINT ["/eigen/bin/tls-client"]

