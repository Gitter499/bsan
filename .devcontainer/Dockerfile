FROM rustlang/rust:nightly-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    cmake \
    clang \
    curl \
    wget \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*
ENV CC=/usr/bin/clang
ENV CXX=/usr/bin/clang++