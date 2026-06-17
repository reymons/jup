.PHONY: example-server example-client example-gen-sig

example-server:
	go run ./example/client-server/.

example-client:
	CLIENT=1 go run ./example/client-server/.

example-gen-sig:
	go run ./example/generate-signature/. --out=$(PWD)/example/client-server/signature/key.ed25519
