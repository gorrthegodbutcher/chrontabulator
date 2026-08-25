# Build ../spdk-dpdk-ubuntu's Dockerfile-single first and tag it
# spdk-dpdk-ubuntu:26.05-local - see this project's README.
FROM spdk-dpdk-ubuntu:26.05-local

# Editor/debug tooling on top of the base image's build toolchain.
# bear records the exact compile commands `make` uses so VS Code's
# IntelliSense can resolve SPDK/DPDK headers without a hand-maintained
# include path list.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    bear \
    clang-tools \
    && rm -rf /var/lib/apt/lists/*
