# Quick start

TL;DR for starting/stopping chrontabulator on the capture host. See
`README.md` for how any of this actually works.

Capture host: `.127` (SSH `mike@192.168.0.127`). Container: `chrontabulator-dev`.
Source lives on the host at `~/chrontabulator`, mounted into the container at
`/workspaces/chrontabulator`.

## Start the container

```
ssh 192.168.0.127
docker start chrontabulator-dev
```

Never `docker rm` + `docker run` to "restart" it - that wipes the container's
own filesystem layer (the standalone DPDK/SPDK build under `/workspace`,
`.devcontainer/setup.sh`'s job, not something `docker start` redoes). If the
container doesn't exist at all, it needs to be created via VS Code's "Dev
Containers: Reopen in Container" first (see `README.md`), not `docker run`.

## Build (after any source change)

Source edited outside the container needs copying in first (the container's
`/workspaces/chrontabulator` is a separate checkout from any host git clone
elsewhere, not a live bind of your working copy):

```
scp src/*.c src/*.h 192.168.0.127:~/chrontabulator/src/
ssh 192.168.0.127 'docker exec chrontabulator-dev bash -c "cd /workspaces/chrontabulator/src && make"'
```

## Start the daemon

```
ssh 192.168.0.127 'docker exec -d chrontabulator-dev bash -c \
  "cd /workspaces/chrontabulator/src && \
   ./chrontabulator -m [1,2] -A 0000:01:00.0 -c ../testdata/nvme_bdev.json \
   -b nvme0n1 --serve --web-port=8080 > /tmp/chrontabulator.log 2>&1"'
```

- `-m [1,2]` - pins DPDK/SPDK to cores 1 and 2 (reserved for this - never
  launch without it, core 0 fights the rest of the system).
- `-A 0000:01:00.0` - the Aquantia NIC's PCIe address.
- `-c ../testdata/nvme_bdev.json` - points `bdev_nvme_attach_controller` at
  the Samsung 990 PRO's PCIe address (`0000:05:00.0`, the M.2 Thunderbolt
  enclosure), bdev name `nvme0`/`nvme0n1`.
- Optional startup tuning: `--write-buffers=<N>` (default 8, max 32) and
  `--write-chunk-kb=<N>` (default 64, max 2048) - both also live-adjustable
  from the web UI once running, no restart needed.

Web UI: **http://192.168.0.127:8091/** (container's 8080, published on the
host as 8091). Log: `/tmp/chrontabulator.log` inside the container.

Check it actually came up:

```
ssh 192.168.0.127 'docker exec chrontabulator-dev tail -n 10 /tmp/chrontabulator.log'
```

Look for `Daemon ready: bdev nvme0n1, port 0, N/4096 segments already recorded`.

## Stop the daemon (graceful)

Always prefer this over a hard kill - it flushes any in-progress recording,
finalizes the segment cleanly, and does a proper NIC teardown (~3s PHY-settle
delay before the process actually exits, so don't panic if `pgrep` still
shows it for a couple seconds after):

```
ssh 192.168.0.127 'docker exec chrontabulator-dev pkill -INT -f "./chrontabulator"'
```

If it's genuinely wedged (stuck admin request, hung write) and SIGINT alone
does nothing after a few seconds:

```
ssh 192.168.0.127 'docker exec chrontabulator-dev pkill -9 -f "./chrontabulator"'
```

## Stop the container

```
ssh 192.168.0.127 'docker stop chrontabulator-dev'
```

Stop the daemon first (above) if a recording might be in progress - stopping
the container just kills everything inside it, same as a hard kill.

## Reboot the host

Stop the daemon gracefully first, then reboot as usual. The container itself
won't auto-start after a reboot - `docker start chrontabulator-dev` once it's
back up (see top of this doc).
