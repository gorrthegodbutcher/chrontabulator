SPDK_ROOT_DIR := /workspace/spdk
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk

APP = chrontabulator

C_SRCS := main.c common.c port_init.c

SPDK_LIB_LIST = $(ALL_MODULES_LIST) event event_bdev

# SPDK's own modules already pull in DPDK's EAL/mempool/ring via
# env_dpdk, but not the ethdev networking layer specifically (SPDK's
# storage/bdev path doesn't need it - we do, for the capture side).
#
# SPDK is built with --with-dpdk against a standalone, full-driver DPDK
# build (see .devcontainer/setup.sh) rather than SPDK's own bundled
# submodule build - SPDK's own dpdkbuild/Makefile hardcodes a storage-only
# driver list with no net/* PMDs at all (no NIC support), since SPDK
# itself never needs one. The standalone build compiles from the same
# already-patched /workspace/spdk/dpdk submodule tree, just via plain
# meson/ninja instead of SPDK's restricted wrapper, and installs a
# libdpdk.pc that already covers every built driver correctly (matching
# how dpdk-app-example links against the same build with no extra flags).
CFLAGS += $(shell pkg-config --cflags libdpdk)
LDFLAGS += $(shell pkg-config --libs libdpdk)

# This DPDK build detects itself as statically linked (rte_bus_pci/rte_eal
# are already embedded in any binary built against it - confirmed via
# dpdk-testpmd, built from this same install, showing the same "static
# linkage" detection). That means net/atlantic must be linked the same
# way: loading it as a runtime plugin via EAL's -d flag pulls in a SECOND,
# dynamically-loaded copy of rte_bus_pci as net_atlantic.so's own shared
# dependency, which double-registers global state (UIO_RESOURCE_LIST
# tailq) against the already-static copy and panics. Whole-archive static
# linking avoids that: one copy of everything, resolved at link time.
# -l:librte_net_atlantic.a (not -lrte_net_atlantic) is needed because a
# .so of the same driver also exists in the same libdir and would
# otherwise win the search order, then get silently dropped by
# --as-needed since nothing calls its symbols directly (registration
# happens via a constructor attribute, invisible to the linker).
LDFLAGS += -Wl,--whole-archive -l:librte_net_atlantic.a -Wl,--no-whole-archive

include $(SPDK_ROOT_DIR)/mk/spdk.app.mk
