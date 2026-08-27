#ifndef RECORD_H
#define RECORD_H

#include <stdint.h>

#define CHRONO_MAGIC_U64(a, b, c, d, e, f, g, h) \
	((uint64_t)(uint8_t)(a) | ((uint64_t)(uint8_t)(b) << 8) | \
	 ((uint64_t)(uint8_t)(c) << 16) | ((uint64_t)(uint8_t)(d) << 24) | \
	 ((uint64_t)(uint8_t)(e) << 32) | ((uint64_t)(uint8_t)(f) << 40) | \
	 ((uint64_t)(uint8_t)(g) << 48) | ((uint64_t)(uint8_t)(h) << 56))

#define CHRONO_RECORD_MAGIC     CHRONO_MAGIC_U64('C', 'H', 'R', 'R', 'E', 'C', '1', ' ')

/* CHRONO_SUPERBLOCK_MAGIC_V1 identified block 0 in the original,
 * pre-segment format (a single chrono_superblock, one capture per
 * device). Nothing writes this magic anymore - it's kept only so --init
 * can recognize an old V1 device as "has real prior data on it" and
 * still refuse to reformat it without --force, the same as it would for
 * a populated V2 volume. Migrating V1 contents forward is out of scope. */
#define CHRONO_SUPERBLOCK_MAGIC_V1 CHRONO_MAGIC_U64('C', 'H', 'R', 'S', 'B', 'L', 'K', '1')

#define CHRONO_VOLUME_MAGIC  CHRONO_MAGIC_U64('C', 'H', 'R', 'V', 'O', 'L', '2', ' ')
#define CHRONO_SEGMENT_MAGIC CHRONO_MAGIC_U64('C', 'H', 'R', 'S', 'E', 'G', '1', ' ')

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

#define CHRONO_FORMAT_VERSION 2   /* V1 = single superblock, one capture per
				   * device (CHRONO_SUPERBLOCK_MAGIC_V1 above,
				   * no longer written). V2 = volume header +
				   * fixed segment TOC, this file. */

/* Segment slots reserved in the TOC at --init time. One slot costs
 * exactly one bdev block (see chrono_segment_entry / the TOC layout
 * comment on chrono_volume_header below), so this is 2-16MB of device
 * space total depending on block size - immaterial next to any real
 * capture drive's capacity. Sized for "a special-purpose capture
 * appliance running periodic ~20-minute sessions", not for arbitrary
 * scale: even at an aggressive 50 captures/day this covers ~80 days
 * before a fresh --init --force is needed. Growing this in place is out
 * of scope for this format version - a full TOC means a fresh --init,
 * same as running out of device space entirely. */
#define CHRONO_TOC_SLOT_COUNT 4096

/* A segment's lifecycle, stored as a plain uint32_t (not this enum type)
 * in chrono_segment_entry.state so the on-disk width is never at the
 * mercy of a compiler's enum sizing. */
enum chrono_segment_state {
	CHRONO_SEGMENT_FREE      = 0, /* slot never claimed - matches a
					* freshly --init'd, zero-filled TOC
					* block exactly, so "state == 0" and
					* "never written" are the same thing,
					* no ambiguity. */
	CHRONO_SEGMENT_OPEN      = 1, /* claimed: either a capture is
					* currently running, or the process
					* that claimed it crashed before
					* finalizing. record_count,
					* dropped_count, block_count, and
					* wall_clock_end_* are NOT
					* authoritative while OPEN - a reader
					* must not trust them. Recovering an
					* OPEN segment's raw records after a
					* crash is out of scope. */
	CHRONO_SEGMENT_FINALIZED = 2, /* clean shutdown - every field below
					* is authoritative. */
	CHRONO_SEGMENT_DELETED   = 3, /* user-requested delete (web UI or a
					* future CLI equivalent) - hidden from
					* listings/dumps by default, but every
					* other field is left exactly as it
					* was at finalize (or at claim, if
					* deleting an abandoned OPEN segment) -
					* explicitly inspecting a deleted entry
					* still shows accurate historical
					* counts. Disk space is NOT reclaimed,
					* consistent with next_data_block's
					* documented behavior above - only
					* --init --force reformats the device. */
};

/* Block 0 of a formatted device. Self-describing: every other region's
 * location is stored here explicitly rather than assumed from a
 * formula, so a reader only ever needs to read block 0 first. Written
 * once by --init, then re-written in place exactly twice per capture
 * segment's lifetime: once when a segment claims a TOC slot
 * (next_segment_id advances) and once when it finalizes cleanly
 * (next_data_block advances) - see main.c's claim/finalize flow for the
 * exact write ordering and why the two updates are NOT symmetric
 * (finalize writes the header before the TOC slot, the opposite of
 * claim, specifically so a crash between the two writes can never lose
 * already-written segment data - see the comment above
 * finalize_segment_and_stop() in main.c).
 *
 * On-disk layout this header describes:
 *   block 0:                          this struct
 *   blocks [toc_start_block, data_start_block):
 *                                      TOC array - one chrono_segment_entry
 *                                      per block, index == segment_id
 *   blocks [data_start_block, device end):
 *                                      segment data, allocated by the
 *                                      next_data_block high-water mark
 */
struct chrono_volume_header {
	uint64_t magic;              /* CHRONO_VOLUME_MAGIC once --init has
				       * formatted this device. Anything else
				       * here - including the old
				       * CHRONO_SUPERBLOCK_MAGIC_V1, or
				       * genuinely blank/foreign bytes - means
				       * "not a valid V2 volume". */
	uint32_t version;            /* CHRONO_FORMAT_VERSION this volume was
				       * formatted with. */
	uint32_t block_size;          /* bdev block_size in effect when
				       * --init wrote this header. Every
				       * offset below (toc_start_block,
				       * data_start_block, next_data_block,
				       * every segment's start_block) is in
				       * units of THIS block size. A later run
				       * confirms the bdev's current
				       * block_size still matches before
				       * trusting any of it - cheap insurance
				       * against ever misinterpreting offsets
				       * on a mismatched device. */
	uint32_t toc_slot_count;      /* segment slots reserved in the TOC,
				       * fixed at --init time (see
				       * CHRONO_TOC_SLOT_COUNT above). */
	uint32_t next_segment_id;     /* next TOC slot index to claim
				       * (0-based). Incremented on every
				       * claim, whether or not the previous
				       * claim ever finalized - this
				       * guarantees two segments never alias
				       * the same slot, even across a crash
				       * that left one orphaned. */
	uint64_t toc_start_block;     /* device-absolute block where the TOC
				       * array begins (== 1, right after this
				       * header block). */
	uint64_t data_start_block;    /* device-absolute first block any
				       * segment's data may ever occupy
				       * (== toc_start_block +
				       * toc_slot_count). */
	uint64_t next_data_block;     /* high-water mark: first free block in
				       * the data area. Advances only when a
				       * segment finalizes cleanly. An OPEN
				       * segment that crashes without
				       * finalizing leaves this untouched, so
				       * the next run's segment reuses the
				       * same start_block and silently
				       * overwrites the orphaned segment's
				       * data - accepted, documented;
				       * recovering an orphaned segment is out
				       * of scope. */
	uint64_t init_wall_clock_sec; /* CLOCK_REALTIME seconds when --init
				       * formatted this device - purely
				       * informational. */
	uint64_t reserved[4];         /* room for future header fields
				       * without moving toc_start_block. */
};

/* One entry in the TOC array (blocks [toc_start_block, data_start_block)
 * on a formatted device) - exactly one bdev block per segment, addressed
 * directly by segment_id (block toc_start_block + segment_id), so both
 * claiming and finalizing a segment are single-block writes with no
 * neighboring slots to preserve. Struct is smaller than a block; the
 * rest of the block is zero-padded by the writer. */
struct chrono_segment_entry {
	uint64_t magic;                 /* CHRONO_SEGMENT_MAGIC once this
					  * slot has been claimed (state !=
					  * FREE); 0 in a never-claimed slot,
					  * matching a freshly --init'd TOC
					  * block exactly. */
	uint32_t segment_id;            /* == this slot's index - carried in
					  * the entry itself so a copy read
					  * off disk is self-identifying. */
	uint32_t state;                 /* chrono_segment_state. */
	uint64_t start_block;           /* device-absolute first block of
					  * this segment's record data -
					  * written once at claim time, never
					  * changes. */
	uint64_t block_count;           /* blocks actually written by this
					  * segment. 0 while OPEN; set once, at
					  * finalize. */
	uint32_t write_chunk_bytes;     /* ctx->buf_size at claim time - the
					  * write chunk size this segment's
					  * data was actually packed with.
					  * Write chunk size is live-tunable
					  * per daemon session (see
					  * MAX_WRITE_BUFFERS's comment in
					  * chrono_ctx.h), so it can differ
					  * segment to segment, or from
					  * whatever a later reader's own
					  * ctx->buf_size happens to be -
					  * readers MUST use this stored value
					  * (not their own current buf_size) to
					  * walk this segment's records, or a
					  * chunk-boundary zero-padding gap
					  * lands at the wrong offset and looks
					  * like a corrupt/overrunning record. */
	uint64_t record_count;
	uint64_t dropped_count;
	uint64_t first_capture_tsc;     /* rte_rdtsc() of this segment's
					  * first record. */
	uint64_t last_capture_tsc;      /* rte_rdtsc() of this segment's last
					  * record. */
	uint64_t tsc_hz;                 /* rte_get_tsc_hz() for this run -
					  * stored per-segment (not assumed
					  * global) so a reader can convert
					  * this segment's own tsc deltas to
					  * seconds without assuming it
					  * matches any other segment's run. */
	uint64_t wall_clock_start_sec;   /* CLOCK_REALTIME seconds since
					  * epoch when this segment was
					  * claimed - the real-world "when" a
					  * listing needs, since capture_tsc
					  * alone is only meaningful relative
					  * to other captures in the same
					  * boot. */
	uint32_t wall_clock_start_nsec;
	uint64_t wall_clock_end_sec;     /* CLOCK_REALTIME at finalize; 0
					  * while OPEN. */
	uint32_t wall_clock_end_nsec;
};

#endif
