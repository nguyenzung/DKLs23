# Makefile cho workspace DKLS23
# Các rule cơ bản: build, release, test, fmt, clippy, clean, wasm helper, toolchain-nightly

SHELL := /bin/bash
CRATE_CORE := dkls23-core
CRATES := dkls23-core dkls23-secp256k1 dkls23-secp256r1

# Test configuration (override from environment if needed):
# Example: make TEST_FLAGS="" TEST_FEATURES="--features serde" test
TEST_FLAGS ?= --release
TEST_FEATURES ?=

.PHONY: all build release test test-% test-core test-workspace-release test-ci fmt fmt-fix clippy clean wasm-target-add wasm-build wasm-bindgen wasm-pack toolchain-nightly help wasm-demo-build wasm-demo-serve wasm-demo

all: build

# Build
build:
	cargo build --workspace

release:
	cargo build --workspace --release

# Tests (use TEST_FLAGS/TEST_FEATURES; default runs release tests)
test:
	cargo test --workspace $(TEST_FLAGS) $(TEST_FEATURES)

# Run tests for a specific crate (honors TEST_FLAGS/TEST_FEATURES)
test-%:
	cargo test -p $* $(TEST_FLAGS) $(TEST_FEATURES)

# Shortcut: run core crate tests in release with recommended features
test-core:
	cargo test -p $(CRATE_CORE) --no-fail-fast $(TEST_FLAGS) --features "serde insecure-rng"

# Shortcut: run full workspace tests in release
test-workspace-release:
	cargo test --workspace --release

# CI-friendly test target: run full workspace tests in release with recommended features
# Use this in CI pipelines: `make test-ci`
test-ci:
	cargo test --workspace --release --features "serde insecure-rng"

# Lints
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

# Clean
clean:
	cargo clean

# WASM helpers
wasm-target-add:
	rustup target add wasm32-unknown-unknown

# Build WASM for core crate (no JS bindings)
wasm-build:
	cargo build -p $(CRATE_CORE) --target wasm32-unknown-unknown --release

# Generate JS bindings via wasm-bindgen (assumes wasm-bindgen-cli installed)
wasm-bindgen:
	@WASM_FILE=target/wasm32-unknown-unknown/release/$(CRATE_CORE).wasm; \
	if [ -f "$$WASM_FILE" ]; then \
		wasm-bindgen "$$WASM_FILE" --out-dir pkg --target web; \
	else \
		echo "WASM not found. Run 'make wasm-build' first."; exit 1; \
	fi

# Use wasm-pack to build a package for JS (requires wasm-pack installed)
wasm-pack:
	cd $(CRATE_CORE) && wasm-pack build --target web --release

# WASM demo: build the wasm-runner-js (example) into top-level pkg/wasm-runner-js
wasm-demo-build:
	@echo "Building wasm demo (wasm-runner-js) with wasm-pack...";
	cd examples/wasm-demo/wasm-runner && wasm-pack build --target web --out-dir ../../../pkg --release

# Serve repository root on http://localhost:8000 (background)
wasm-demo-serve:
	@echo "Serving repo root at http://localhost:8000/";
	@python3 -m http.server 8000 &
	@sleep 1;
	@echo "Visit http://localhost:8000/examples/wasm-demo/index.html"

# Build + serve convenience target
wasm-demo: wasm-demo-build wasm-demo-serve
	@echo "WASM demo built and served. Open http://localhost:8000/examples/wasm-demo/index.html"

# Install nightly toolchain and create rust-toolchain.toml at repo root
toolchain-nightly:
	rustup toolchain install nightly
	printf '[toolchain]\nchannel = "nightly"\n' > rust-toolchain.toml
	echo "Created rust-toolchain.toml (nightly). Use 'cargo +nightly build' or just 'cargo build' if your toolchain defaulted."

# Help / usage
help:
	@echo "Makefile targets:"
	@echo "  make           (default => build workspace)"
	@echo "  make build     (cargo build --workspace)"
	@echo "  make release   (cargo build --workspace --release)"
	@echo "  make test      (cargo test --workspace) - honors TEST_FLAGS/TEST_FEATURES"
	@echo "  make test-<crate> (run tests for specific crate) - honors TEST_FLAGS/TEST_FEATURES"
	@echo "  make test-core (run core crate tests in release with 'serde insecure-rng')"
	@echo "  make test-workspace-release (run full workspace tests in release)"
	@echo "  make test-ci   (run full workspace tests in release with recommended features)"
	@echo "  make fmt       (check rustfmt)"
	@echo "  make fmt-fix   (apply rustfmt)"
	@echo "  make clippy    (run clippy and treat warnings as errors)"
	@echo "  make clean     (cargo clean)"
	@echo "  make wasm-target-add (add wasm target)"
	@echo "  make wasm-build (build wasm for $(CRATE_CORE))"
	@echo "  make wasm-bindgen (run wasm-bindgen on built wasm)"
	@echo "  make wasm-pack (run wasm-pack build in $(CRATE_CORE))"
	@echo "  make wasm-demo-build (build the examples/wasm-demo/wasm-runner with wasm-pack)"
	@echo "  make wasm-demo-serve (serve repo root on http://localhost:8000)"
	@echo "  make wasm-demo (build + serve wasm demo)"
	@echo "  make toolchain-nightly (install nightly and create rust-toolchain.toml)"
