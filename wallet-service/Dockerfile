# Use the correct Go version
FROM golang:1.21-alpine

WORKDIR /app

# Copy go.mod and go.sum first (to leverage Docker caching)
COPY go.mod go.sum ./

# Install dependencies
RUN go mod tidy

# Copy the rest of the app
COPY . .

# Build the app
RUN go build -o main .