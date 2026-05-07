FROM golang:1.25 AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -extldflags '-static'" \
    -o /out/ecloud-drain-watcher \
    ./cmd/ecloud-drain-watcher

FROM scratch
COPY --from=builder /out/ecloud-drain-watcher /eigen/bin/ecloud-drain-watcher
ENTRYPOINT ["/eigen/bin/ecloud-drain-watcher"]
