FROM golang:1.24.2-bookworm AS builder

RUN apt-get update && apt-get install -y \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

ENV KMS_VERSION=master

RUN git clone https://github.com/Layr-Labs/eigenx-kms-go && \
    cd eigenx-kms-go && \
    git checkout $KMS_VERSION && \
    make deps && make build/cmd/kmsClient/static


FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/eigenx-kms-go/bin/kms-client /eigen/bin/eigenx-kms-client
ENTRYPOINT ["/eigen/bin/eigenx-kms-client"]
