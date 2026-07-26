# Build a static agent binary.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/vritti-agent ./cmd/agent

# The agent talks to the host Docker daemon; it needs only the socket + its data dir.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/vritti-agent /usr/local/bin/vritti-agent
ENTRYPOINT ["/usr/local/bin/vritti-agent"]
