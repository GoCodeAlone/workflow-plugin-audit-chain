.PHONY: proto-gen build test test-migrations vet

# Regenerate Go bindings from proto/audit.proto.
# Requires: protoc + protoc-gen-go (go install google.golang.org/protobuf/cmd/protoc-gen-go@latest)
proto-gen:
	protoc \
		--proto_path=proto \
		--go_out=gen \
		--go_opt=paths=source_relative \
		proto/audit.proto

build:
	GOWORK=off go build ./...

test:
	GOWORK=off go test ./... -v -race -count=1

test-migrations:
	GOWORK=off go test ./chain/... -v -race -count=1 -run TestMigrations

vet:
	GOWORK=off go vet ./...
