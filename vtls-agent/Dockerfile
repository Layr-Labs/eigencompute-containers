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
    -o /out/vtls-agent \
    ./cmd/vtls-agent

FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/vtls-agent /eigen/bin/vtls-agent
ENTRYPOINT ["/eigen/bin/vtls-agent"]




