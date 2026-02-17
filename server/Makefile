.PHONY: all proto build clean run

all: proto build

proto:
	@echo "Generating protobuf code..."
	@mkdir -p proto
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/*.proto || echo "Warning: protoc not available, using pre-generated files"

build:
	@echo "Building server..."
	@go build -o bin/mailx-server cmd/server/main.go

clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f *.db
	@rm -f server_key.json

run:
	@echo "Running server..."
	@./bin/mailx-server

test:
	@echo "Running tests..."
	@go test ./...
