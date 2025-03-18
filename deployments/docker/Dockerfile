FROM rust:1.70 as builder

# eBPF/XDP 의존성 설치
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    clang llvm libelf-dev build-essential linux-headers-generic

WORKDIR /usr/src/swift-guard

# Cargo.toml 및 Cargo.lock 복사 (캐싱 최적화)
COPY Cargo.toml Cargo.lock ./
COPY wasm-module/Cargo.toml ./wasm-module/
RUN mkdir -p src/bin wasm-module/src \
    && touch src/lib.rs src/bin/xdp_ctl.rs src/bin/wasm_inspector.rs wasm-module/src/lib.rs

# 의존성 미리 빌드
RUN cargo build --release

# 소스 코드 복사 및 최종 빌드
COPY . .
RUN cargo build --release && \
    cd bpf && make

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libelf1 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/swift-guard

COPY --from=builder /usr/src/swift-guard/target/release/xdp-ctl .
COPY --from=builder /usr/src/swift-guard/target/release/wasm-inspector .
COPY --from=builder /usr/src/swift-guard/bpf/*.o ./bpf/

ENTRYPOINT ["/opt/swift-guard/xdp-ctl"]
