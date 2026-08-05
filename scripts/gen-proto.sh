#!/usr/bin/env bash
# Regenerate Go bindings for the agent<->cloud contract (proto/agent/v1/agent.proto -> gen/).
#
# Reproducible without global installs: the two protoc plugins are built from modules already
# required by go.mod into ./.bin (git-ignored) and put on PATH; buf runs via a pinned `go run`
# so it never enters go.mod/go.sum (buf's dependency tree is enormous).
set -euo pipefail
cd "$(dirname "$0")/.."

BUF_VERSION="v1.72.0"
BIN="$PWD/.bin"
mkdir -p "$BIN"

echo "building protoc plugins into .bin ..."
go build -o "$BIN/protoc-gen-go" google.golang.org/protobuf/cmd/protoc-gen-go
go build -o "$BIN/protoc-gen-connect-go" connectrpc.com/connect/cmd/protoc-gen-connect-go

echo "running buf generate (buf $BUF_VERSION via go run) ..."
PATH="$BIN:$PATH" go run "github.com/bufbuild/buf/cmd/buf@$BUF_VERSION" generate

echo "done -> gen/"
