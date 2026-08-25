#!/bin/bash
# Runs once when the dev container is first created (devcontainer.json's
# postCreateCommand). Three stages, each skipped on later reopens once
# already done:
#
# 1. A standalone, full-driver DPDK build from the same already-patched
#    /workspace/spdk/dpdk submodule tree the base image ships - NOT a
#    second clone, just a different meson invocation. SPDK's own bundled
#    DPDK build only compiles storage-relevant driver classes (no NIC
#    PMDs at all), so this project needs its own build with the default
#    driver set to get atlantic support. Matches dpdk-app-example's own
#    setup.sh build of the same source tree.
# 2. SPDK itself, via --with-dpdk pointing at stage 1's install, so SPDK
#    links against that DPDK instead of building its own restricted copy.
#    make install also copies its own set of DPDK shared libraries into
#    spdk_package/lib - symlinked back to stage 1's originals afterward,
#    or an app that ends up with two independently-loaded copies of
#    rte_bus_pci/rte_eal panics (UIO_RESOURCE_LIST tailq double
#    registration). See README.md's "Why a separate DPDK build" section
#    for the full story - this was not obvious and cost real debugging
#    time to work out.
# 3. This project's own binary, statically linked against stage 1's
#    librte_net_atlantic.a (see src/Makefile) - not loaded as a runtime
#    plugin, for the same static/dynamic duplication reason as stage 2.
set -euo pipefail

WORKSPACE_DIR="$PWD"

echo "==> Building standalone DPDK (first-time setup takes a few minutes)..."
cd /workspace/spdk/dpdk
[ -f /workspace/dpdk_build/build.ninja ] || meson setup /workspace/dpdk_build
ninja -C /workspace/dpdk_build
ninja -C /workspace/dpdk_build install
ldconfig

echo "==> Building SPDK against it..."
cd /workspace/spdk
[ -f mk/config.mk ] || ./configure --prefix=/workspace/spdk_package --disable-tests \
	--disable-unit-tests --with-dpdk=/usr/local
make -j"$(nproc)"
make install

echo "==> Deduplicating DPDK shared libraries SPDK's install copied..."
cd /workspace/spdk_package/lib
for f in librte_*.so.*; do
	[ -L "$f" ] && continue
	target="/usr/local/lib/x86_64-linux-gnu/$f"
	[ -f "$target" ] && ln -sf "$target" "$f"
done
ldconfig

echo "==> Building chrontabulator..."
cd "$WORKSPACE_DIR/src"
bear -- make
