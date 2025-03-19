#!/bin/bash
# WASM module build script for Swift-Guard

set -e

# Directory containing module source files
MODULES_DIR="modules"
# Output directory for compiled WASM modules
OUTPUT_DIR="modules"
# Rust WASM target
WASM_TARGET="wasm32-unknown-unknown"

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo "Error: Rust compiler not found. Please install Rust first."
    echo "Visit https://rustup.rs for installation instructions."
    exit 1
fi

# Check if wasm32 target is installed
if ! rustup target list | grep -q "$WASM_TARGET installed"; then
    echo "Installing wasm32 target..."
    rustup target add "$WASM_TARGET"
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Find all Rust files in the modules directory
RUST_FILES=$(find "$MODULES_DIR" -name "*.rs" -type f)

if [ -z "$RUST_FILES" ]; then
    echo "No Rust files found in $MODULES_DIR directory."
    exit 0
fi

# Build each module
for rust_file in $RUST_FILES; do
    base_name=$(basename "$rust_file" .rs)
    wasm_file="$OUTPUT_DIR/$base_name.wasm"
    
    echo "Building $base_name..."
    
    # Create temporary directory for the build
    temp_dir=$(mktemp -d)
    trap 'rm -rf "$temp_dir"' EXIT
    
    # Create temporary cargo project
    cd "$temp_dir"
    cargo init --lib
    
    # Configure the project for WASM
    cat > Cargo.toml << EOF
[package]
name = "$base_name"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[profile.release]
lto = true
opt-level = 's'
strip = true

[dependencies]
EOF
    
    # Copy the source file
    cp "$OLDPWD/$rust_file" src/lib.rs
    
    # Build the WASM module
    cargo build --release --target "$WASM_TARGET"
    
    # Copy the resulting WASM file to the output directory
    cp "target/$WASM_TARGET/release/$base_name.wasm" "$OLDPWD/$wasm_file"
    
    # Return to the original directory
    cd "$OLDPWD"
    
    echo "Successfully built $wasm_file"
done

echo "All WASM modules built successfully!"
