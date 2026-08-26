# chrontabulator

A single SPDK-native process that captures UDP packets off a DPDK-owned
NIC and records them straight to a raw NVMe bdev, with enough per-record
metadata to sort them back into correct order in a later, separate replay
pass. Built on the same `spdk-dpdk-ubuntu` base image as its sibling
projects, but unlike `dpdk-app-example` (plain DPDK) or `spdk-app-example`
(SPDK bdev only), this project runs DPDK ethdev RX polling and
`spdk_bdev_*` NVMe writes in the same SPDK reactor.

**The actual goal:** capture ~20 minutes of received network traffic to
NVMe, then play it back sorted into correct order rather than arrival
order. That distinction matters because it isn't hypothetical - a
switch-induced reordering test in `dpdk-app-example`'s own investigation
showed real traffic can arrive with sequence jumps exceeding 10,000
positions while losing almost nothing, so out-of-order arrival is the
normal case to design for. `dpdk-app-example` is used as-is (unmodified)
as the traffic generator for testing this project; sorted replay itself
is a later phase, not built yet.

## Prerequisites

1. Build and tag the base image, from the sibling `spdk-dpdk-ubuntu` repo:
   ```
   cd ../spdk-dpdk-ubuntu
   docker build -f Dockerfile-single -t spdk-dpdk-ubuntu:26.05-local .
   ```
2. A spare, unpartitioned NVMe drive (not the OS boot drive) bound to
   `vfio-pci`, the same way `spdk-app-example`'s NVMe section and
   `dpdk-app-example`'s "Running against real hardware" section describe
   for a drive/NIC respectively - the mechanism is identical either way.
   Find the drive's PCIe address first: `readlink -f /sys/block/<dev>/device`.
3. The capture NIC bound to `vfio-pci` too, same mechanism.
4. Install VS Code's "Dev Containers" extension (`ms-vscode-remote.remote-containers`).

## Getting started

Open this folder in VS Code, "Dev Containers: Reopen in Container". First
launch builds two things (several minutes total, see `.devcontainer/setup.sh`):
a standalone, full-driver DPDK build from the same patched
`/workspace/spdk/dpdk` submodule tree the base image ships (**not** a
second clone - see "Why a separate DPDK build" below), then SPDK itself
via `./configure --with-dpdk=<that build> && make && make install`.
Subsequent launches skip both since they're already configured.

## Why a separate DPDK build, and why static linking

SPDK's own bundled DPDK build (`dpdkbuild/Makefile`'s `DPDK_DRIVERS` list)
only compiles the driver classes SPDK's storage code actually uses - bus,
mempool, power, crypto/compress. **No NIC drivers at all.** Since this
project needs a real NIC PMD (atlantic) alongside SPDK's bdev machinery
in the same process, SPDK is built with `--with-dpdk=<dir>` against a
second, unrestricted build of the exact same already-patched DPDK source,
compiled with plain `meson`/`ninja` instead of SPDK's wrapper.

That still isn't enough on its own. This DPDK build detects itself as
statically linked - `rte_bus_pci`/`rte_eal` end up embedded directly in
any binary built against it (SPDK needs `rte_bus_pci` for its own
NVMe/vfio-pci access). Loading the atlantic driver as a runtime plugin via
EAL's `-d` flag (the pattern `dpdk-app-example` uses) pulls in a *second*,
dynamically-loaded copy of `rte_bus_pci` as `librte_net_atlantic.so`'s own
shared-library dependency - two copies of the same global driver registry
in one process panics immediately (`UIO_RESOURCE_LIST tailq is already
registered`). The fix is to link `librte_net_atlantic.a` directly into
this project's own binary instead (see `src/Makefile`'s `--whole-archive
-l:librte_net_atlantic.a` block) - one copy of everything, resolved at
link time, no `-d` needed at runtime at all.

(`dpdk-app-example`'s README documents a related but different version of
this same class of bug: SPDK's install copies its own set of DPDK shared
libraries, and `LD_LIBRARY_PATH` resolution order can silently pick the
wrong copy. That project avoids it by never linking against SPDK in the
first place. This project can't take that shortcut since it needs SPDK's
bdev machinery, so it resolves the underlying conflict at the source
instead: one external DPDK build, everything link-time static.)

## Usage

A device must be formatted once before its first capture:
```
./chrontabulator -A <nic-pci-addr> -c <bdev.json> -b <bdev-name> --init [--force]
```
`--force` is required to reformat a device that already has a
chrontabulator volume (any version) or a legacy pre-segment capture on
it - a blank/foreign device doesn't need it. Reformatting makes every
existing segment on the device unreadable.

**Capture** (each run claims its own segment - multiple captures can
coexist on one formatted device without overwriting each other):
```
./chrontabulator -A <nic-pci-addr> -c <bdev.json> -b <bdev-name> -P <udp-port> [-C <count>] [-M <mtu>] [-F]
```
- `-c` - SPDK bdev config JSON (see `testdata/nvme_bdev.json` for the
  `bdev_nvme_attach_controller` template - point `traddr` at the capture
  drive's PCIe address)
- `-b` - the bdev name that config produces (`bdev_nvme_attach_controller`
  with `name: "nvme0"` yields `nvme0n1`)
- `-P` - UDP destination port to capture; everything else is ignored
- `-C` - stop after this many records (default 0 = unlimited, Ctrl+C to stop)
- `-M` / `-F` - MTU / restrict to 10G link speed, same meaning as the
  equivalent `dpdk-app-example` receiver flags

Ctrl+C (or `-C` being reached) flushes any partially-full write buffer and
finalizes the segment cleanly. A segment killed before finalizing (crash,
`kill -9`) shows up as `OPEN` in `-D`'s listing - its data isn't lost, but
its space gets silently reused by the next capture that runs (recovering
an orphaned segment is out of scope for now).

**List segments** (default `-D` behavior) or **dump one segment's
records** (to verify the on-disk format without trusting a long run
blind):
```
./chrontabulator -A <nic-pci-addr> -c <bdev.json> -b <bdev-name> -D
./chrontabulator -A <nic-pci-addr> -c <bdev.json> -b <bdev-name> -D -S <segment-id>
```
No NIC/DPDK setup happens in dump/list or `--init` modes - `-P` isn't
required, and `-A` only matters because SPDK still parses it from the
combined arg list even though nothing uses it here.

**Daemon + web UI** (persistent process - brings the NIC up once, then
recording is started/stopped repeatedly from a browser without paying
that cost again):
```
./chrontabulator -A <nic-pci-addr> -c <bdev.json> -b <bdev-name> --serve [--web-port=<port>] [-P <default-port>] [-C <default-count>]
```
Open `http://<host>:<web-port>/` (default 8080, `0` = headless/no web
server). `-P`/`-C` given at startup become defaults for sessions started
from the UI (or via `POST /recording/start?port=&count_limit=`), not a
hard requirement - the port can also be set per-session from the page.
`-M`/`-F` are daemon-start-time only (tied to the one-time NIC bring-up).

The dashboard shows live NIC/NVMe housekeeping, lets you start/stop
recording, browse the table of contents, and view or delete a segment
(`/segments.json`, `/segments/<id>/records.json` - paginated,
`?offset=&limit=`, capped at 2000/request - and `POST
/segments/<id>/delete`). Deleting a segment hides it from the default
listing (`?include_deleted=1` shows it again with its original counts
intact) but doesn't reclaim its disk space, same as an orphaned segment.
"Delete" here is distinct from real playback/re-transmission, which isn't
built yet - viewing a segment's records is read-only.

SPDK's bdev/thread APIs can't be called off the reactor thread, so the
embedded web server runs on its own pthread (same accept-loop shape as
`dpdk-app-example`'s `web_status.c`) and bridges any request that needs
real I/O (start/stop, segment list/records/delete) back onto the reactor
via `spdk_thread_send_msg()` plus a bounded (3s) condvar wait - see
`src/chrono_admin.c`. Pure status polling (`/status.json`, NIC link/hw
stats, live record counts) is served directly from lock-free atomics, no
bridging needed.

## On-disk format

See `src/record.h` for the exact layout. Block 0 holds a
`chrono_volume_header` (written once by `--init`); a fixed table of
contents right after it holds one `chrono_segment_entry` per capture
segment; segment data fills the rest of the device, allocated by a
high-water mark that only advances when a segment finalizes cleanly - an
orphaned (crashed) segment just gets silently overwritten by the next
run, never leaked space. Records within a segment are written back-to-back
into fixed-size chunks sized to the bdev's write-unit granularity,
zero-padded at flush time so a reader can always tell real records from
unwritten space via `magic == 0`. Each record carries the sender's own
sequence number *and* this recorder's own `rte_rdtsc()` capture
timestamp - the sequence number alone resets across sender restarts and
isn't ordering-authoritative on its own, so `capture_tsc` is the real
signal a later sorted-replay pass should use.

## Roadmap

Working now: capture to independently-addressable segments on one
device, `-D`/`-D -S` listing and per-segment readback verification, safe
device `--init`, and a persistent `--serve` daemon with an embedded web
UI for live NIC/NVMe housekeeping, recording control, and browsing/
deleting/viewing segments. Planned, not started: real playback
(re-transmitting a segment's captured packets, as opposed to today's
read-only view/export), and sorted replay across segments by
`capture_tsc`.
