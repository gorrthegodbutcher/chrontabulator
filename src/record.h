#ifndef RECORD_H
#define RECORD_H

#include <stdint.h>

#define CHRONO_MAGIC_U64(a, b, c, d, e, f, g, h) \
	((uint64_t)(uint8_t)(a) | ((uint64_t)(uint8_t)(b) << 8) | \
	 ((uint64_t)(uint8_t)(c) << 16) | ((uint64_t)(uint8_t)(d) << 24) | \
	 ((uint64_t)(uint8_t)(e) << 32) | ((uint64_t)(uint8_t)(f) << 40) | \
	 ((uint64_t)(uint8_t)(g) << 48) | ((uint64_t)(uint8_t)(h) << 56))

#define CHRONO_RECORD_MAGIC     CHRONO_MAGIC_U64('C', 'H', 'R', 'R', 'E', 'C', '1', ' ')
#define CHRONO_SUPERBLOCK_MAGIC CHRONO_MAGIC_U64('C', 'H', 'R', 'S', 'B', 'L', 'K', '1')

/* One captured packet's worth of metadata, immediately followed by
 * `len` bytes of the packet's application payload (everything after the
 * 8-byte sequence number dpdk-app-example's wire format embeds - see
 * common.h). Records are packed back-to-back into each write buffer;
 * padding (magic == 0) fills any leftover space at the end of a buffer
 * rather than starting a record that would straddle a write boundary,
 * so a reader can always tell real records from padding.
 *
 * seq is the sender's own application-level sequence number - useful,
 * but not authoritative for ordering on its own (see resync_events in
 * the dpdk-app-example investigation this project grew out of - a
 * sender restart resets it to 0). capture_tsc is this recorder's own
 * rte_rdtsc() reading at the moment the packet was pulled off the RX
 * ring - the real ordering signal a later sorted-replay pass should
 * use, since it's assigned locally and monotonically regardless of
 * what the sender's sequence numbering is doing. */
struct chrono_record_hdr {
	uint64_t magic;
	uint64_t seq;
	uint64_t capture_tsc;
	uint32_t len;
	uint32_t reserved;
};

/* Written once, at the end of a clean recording (offset 0 on the bdev -
 * the actual record data starts at block 1, never block 0, so the
 * superblock is always found in a fixed, predictable place regardless
 * of how much or little was actually recorded). tsc_hz lets a later
 * reader convert capture_tsc deltas into wall-clock durations. */
struct chrono_superblock {
	uint64_t magic;
	uint32_t version;
	uint32_t block_size;
	uint64_t record_count;
	uint64_t dropped_count;
	uint64_t first_capture_tsc;
	uint64_t last_capture_tsc;
	uint64_t tsc_hz;
};

#define CHRONO_FORMAT_VERSION 1

#endif
