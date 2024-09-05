FROM golang:1.23.0-alpine3.20 AS builder

WORKDIR /app

COPY scaner/go.mod ./
RUN go mod download

COPY scaner/ .

RUN go build -o image-policy-webhook main.go

FROM alpine:3.20.2

# Install necessary packages and Trivy
RUN apk add --no-cache curl \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Copy the pre-built binary from the builder stage
COPY --from=builder /app/image-policy-webhook /usr/local/bin/image-policy-webhook

# Create a directory for the certificates (these will be mounted via Kubernetes secrets)
RUN mkdir -p /etc/webhook/certs

# Expose port 8080 for the webhook server
EXPOSE 8080

# Set the entry point for the container
CMD ["image-policy-webhook"]