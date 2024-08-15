# Build
FROM golang:1.21.0-alpine AS builder
RUN apk add build-base libpcap-dev
WORKDIR /app
COPY . /app
WORKDIR /app
RUN go mod download
RUN go build .

FROM alpine:3.18.3
RUN apk add nmap libpcap-dev bind-tools ca-certificates nmap-scripts
COPY --from=builder /app/goscanner /usr/local/bin/
ENTRYPOINT ["goscanner"]