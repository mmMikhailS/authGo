PROTO_DIR=api/protobuf
GEN_DIR=internal/common/genproto
OPENAPI_DIR=api/openapi

.PHONY: generate
generate:
	mkdir -p $(GEN_DIR)/auth
	mkdir -p $(GEN_DIR)/twofa
	mkdir -p $(OPENAPI_DIR)

	# Generate Auth
	protoc -I $(PROTO_DIR) \
		--go_out=$(GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=paths=source_relative \
		--openapiv2_out=$(OPENAPI_DIR) --openapiv2_opt=logtostderr=true \
		$(PROTO_DIR)/auth.proto

	# Generate TwoFA
	protoc -I $(PROTO_DIR) \
		--go_out=$(GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=paths=source_relative \
		--openapiv2_out=$(OPENAPI_DIR) --openapiv2_opt=logtostderr=true \
		$(PROTO_DIR)/twofa.proto


.PHONY: generate clean

# 1. Clean old files, 2. Create folders, 3. Run protoc
generate: clean
	mkdir -p $(GEN_DIR)/auth
	mkdir -p $(GEN_DIR)/twofa
	mkdir -p $(OPENAPI_DIR)

	# Generate Auth (Go + Swagger)
	protoc -I $(PROTO_DIR) \
		--go_out=$(GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=paths=source_relative \
		--openapiv2_out=$(OPENAPI_DIR) \
		--openapiv2_opt=logtostderr=true,allow_merge=true,merge_file_name=auth \
		$(PROTO_DIR)/auth.proto

	# Generate TwoFA (Go + Swagger)
	protoc -I $(PROTO_DIR) \
		--go_out=$(GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=paths=source_relative \
		--openapiv2_out=$(OPENAPI_DIR) \
		--openapiv2_opt=logtostderr=true,allow_merge=true,merge_file_name=twofa \
		$(PROTO_DIR)/twofa.proto

clean:
	rm -rf $(GEN_DIR)/auth/*.go
	rm -rf $(GEN_DIR)/twofa/*.go
	rm -rf $(OPENAPI_DIR)/*.swagger.json