FROM golang:1.17-alpine as builder
RUN apk --no-cache add ca-certificates build-base
WORKDIR /istio-security-analyzer/


# Fetch dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . ./
RUN make build

# Create final image
FROM alpine
WORKDIR /
COPY --from=builder /istio-security-analyzer/build/scanner_linux_amd64/scanner .
CMD ["./scanner"]