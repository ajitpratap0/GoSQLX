.PHONY: build serve clean

build:
	GOOS=js GOARCH=wasm go build -o playground/gosqlx.wasm ../wasm/

serve: build
	@echo "Serving at http://localhost:8080"
	cd playground && python3 -m http.server 8080

clean:
	rm -f playground/gosqlx.wasm
