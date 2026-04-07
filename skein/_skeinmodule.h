/*
    _skeinmodule.h
    Copyright 2008, 2009, 2010 Hagen Fürstenau <hagen@zhuliguan.net>
    Some of this code evolved from an implementation by Doug Whiting,
    which was released to the public domain.

    This file is part of PySkein.

    PySkein is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define  SKEIN_256_STATE_WORDS  (4)
#define  SKEIN_512_STATE_WORDS  (8)
#define  SKEIN_1024_STATE_WORDS (16)
#define  SKEIN_MAX_STATE_WORDS  SKEIN_1024_STATE_WORDS

#define  SKEIN_256_BLOCK_BYTES  (8*SKEIN_256_STATE_WORDS)
#define  SKEIN_512_BLOCK_BYTES  (8*SKEIN_512_STATE_WORDS)
#define  SKEIN_1024_BLOCK_BYTES (8*SKEIN_1024_STATE_WORDS)
#define  SKEIN_MAX_BLOCK_BYTES  SKEIN_1024_BLOCK_BYTES


/* Free-threading support: per-object mutex, present only in GIL-disabled builds.
   In regular (GIL) builds the lock macros are no-ops — the GIL is sufficient. */
#ifdef Py_GIL_DISABLED
#  define SKEIN_LOCK(obj)   PyMutex_Lock(&(obj)->lock)
#  define SKEIN_UNLOCK(obj) PyMutex_Unlock(&(obj)->lock)
#else
#  define SKEIN_LOCK(obj)   ((void)0)
#  define SKEIN_UNLOCK(obj) ((void)0)
#endif


/* Python object definitions */

static PyTypeObject skeinType;

struct _skein_state_s;

typedef int (*processor_t)(struct _skein_state_s *,
                           const u08b_t *, size_t, u08b_t);

typedef struct _skein_state_s {
    /* chaining variables and tweak value */
    u64b_t                X[SKEIN_MAX_STATE_WORDS+1];
    u64b_t                T[3];
    processor_t           block_processor;

    /* tree hashing state */
    u64b_t                tree_blocks;
    u64b_t                remaining_tree_blocks;
    u08b_t                remaining_tree_levels;
    struct _skein_state_s *next_tree_level;
} skein_state_t;

typedef struct {
    PyObject_HEAD

    skein_state_t state;

    /* count bytes hashed so far */
    u64b_t        hashed_bytes;

    /* state and digest sizes */
    u64b_t        digestBits;
    u08b_t        stateBytes;

    /* unprocessed bytes buffer */
    u08b_t        b[SKEIN_MAX_BLOCK_BYTES];
    u08b_t        bCnt;
    u08b_t        missing_bits;
        /* number of bits missing from the last byte in b */

#ifdef Py_GIL_DISABLED
    PyMutex       lock;  /* serialises concurrent method calls in free-threaded builds */
#endif
} skeinObject;


typedef struct {
    PyObject_HEAD

    void(*encryptor)(u64b_t *, u64b_t *, const u64b_t *, u64b_t *, int);
    void(*decryptor)(u64b_t *, u64b_t *, const u64b_t *, u64b_t *);
    u64b_t kw[SKEIN_MAX_STATE_WORDS+4];  /* precomputed key schedule */
    Py_ssize_t blockBytes;

#ifdef Py_GIL_DISABLED
    PyMutex lock;  /* serialises concurrent tweak writes vs. encrypt/decrypt */
#endif
} threefishObject;


/*
 * UBI chaining macros
 *
 * Skein processes each input type (key, config, message, …) through a
 * separate UBI (Unique Block Iteration) call.  A UBI call is a sequence of
 * Threefish compressions where:
 *   T[0] is a running byte count (position counter), making each block's
 *        tweak unique within the call, which is essential for UBI's security.
 *   T[1] carries control flags (FIRST, FINAL, BITPAD) and a 6-bit block-type
 *        field in bits 56-62, providing domain separation between input types
 *        so that collisions cannot be constructed across different call types.
 *
 * HASH_INIT   — begin a new UBI call: zero the position counter, set the
 *               FIRST flag and block type, reset the byte buffer.
 * HASH_FINALIZE — end a UBI call: set the FINAL flag (and BITPAD if the last
 *               byte is partial), zero-pad the partial block, then process it.
 * HASH_BLOCK  — process a single, self-contained block (FIRST|FINAL together):
 *               used for fixed-size inputs like the configuration block.
 * HASH_BLOCKS — shorthand for HASH_INIT + streaming update + HASH_FINALIZE.
 */
#define HASH_INIT(sk, type) \
{ \
    sk->state.T[0] = 0; \
    sk->state.T[1] = SKEIN_T1_FLAG_FIRST | ((u64b_t)SKEIN_BLOCK_TYPE_##type<<56); \
    sk->bCnt = 0; \
}

#define HASH_FINALIZE(sk) \
{ \
    sk->state.T[1] |= SKEIN_T1_FLAG_FINAL; \
    if (sk->missing_bits) \
        sk->state.T[1] |= SKEIN_T1_FLAG_BITPAD; \
    if (sk->bCnt < sk->stateBytes) \
        memset(&sk->b[sk->bCnt], 0, sk->stateBytes - sk->bCnt); \
    sk->state.block_processor(&sk->state, sk->b, 1, sk->bCnt); \
}

#define HASH_BLOCK(sk, p, len, type) \
{ \
    sk->state.T[0] = 0; \
    sk->state.T[1] = SKEIN_T1_FLAG_FIRST | SKEIN_T1_FLAG_FINAL | \
                     ((u64b_t)SKEIN_BLOCK_TYPE_##type<<56); \
    if (!sk->state.block_processor(&sk->state, p, 1, len)) \
        goto error; \
}

#define HASH_BLOCKS(sk, p, len, type) \
{ \
    HASH_INIT(sk, type); \
    if (!hash_bytes(sk, p, len)) \
        goto error; \
    HASH_FINALIZE(sk); \
}


/*
 * Numerical constants
 *
 * SKEIN_KS_PARITY: the "C240" constant from spec §2.2.4, value
 *   0x1BD11BDAA9FC1A22.  It is XOR'd with all key words to produce the extra
 *   (N+1)th key schedule word, ensuring the XOR of every subkey injection for
 *   a given word position is always this constant rather than zero.  This
 *   breaks the symmetry that would otherwise allow related-key attacks.
 *
 * T1 flag bits (in the high 64-bit tweak word T1):
 *   FIRST  (bit 62) — set only for the first block of a UBI call, preventing
 *                     extension attacks by tying the block to its position.
 *   FINAL  (bit 63) — set only for the last block, preventing length-extension
 *                     by making the terminal block distinguishable.
 *   BITPAD (bit 55) — set when the last byte is incomplete (partial-byte
 *                     input), so the pad marker can be placed correctly.
 *
 * SKEIN_T1_POS_LEVEL: bit position of the tree level field in T1, used to
 *   increment the level counter when propagating a tree-hash node upward.
 *
 * Block type constants: occupy bits 56-61 of T1; provide domain separation
 *   between the different input types in the UBI chain so that an attacker
 *   cannot reinterpret a key block as a message block or vice versa.
 */
#define U64B_CONST(high, low)  (((u64b_t)high << 32) | (u64b_t)low)
#define SKEIN_KS_PARITY        U64B_CONST(0x1BD11BDA, 0xA9FC1A22)
#define SKEIN_T1_FLAG_FIRST    U64B_CONST(0x40000000, 0x00000000)
#define SKEIN_T1_FLAG_FINAL    U64B_CONST(0x80000000, 0x00000000)
#define SKEIN_T1_FLAG_BITPAD   U64B_CONST(0x00800000, 0x00000000)
#define SKEIN_T1_POS_LEVEL     (112-64)

#define SKEIN_BLOCK_TYPE_KEY    0 /* key, for MAC and KDF */
#define SKEIN_BLOCK_TYPE_CFG    4 /* configuration block */
#define SKEIN_BLOCK_TYPE_PERS   8 /* personalization string */
#define SKEIN_BLOCK_TYPE_PK    12 /* public key */
#define SKEIN_BLOCK_TYPE_KID   16 /* key identifier for KDF */
#define SKEIN_BLOCK_TYPE_NONCE 20 /* nonce */
#define SKEIN_BLOCK_TYPE_MSG   48 /* message processing */
#define SKEIN_BLOCK_TYPE_OUT   63 /* output stage */


/* conversions between bytes and 64-bit words */

#ifdef WORDS_BIGENDIAN  /* compatible with big endian platforms, but slow */
/* static inline: avoids external-linkage definitions in a header, which would
   violate ODR if this header were ever included from more than one translation unit. */
static inline void WORDS_TO_BYTES(u08b_t *dst, const u64b_t *src, size_t bCnt) {
    size_t n;

    for (n=0;n<bCnt;n++)
        dst[n] = (u08b_t) (src[n>>3] >> (8*(n&7)));
}

static inline void BYTES_TO_WORDS(u64b_t *dst, const u08b_t *src, size_t wCnt) {
    size_t n;

    for (n=0;n<8*wCnt;n+=8)
        dst[n/8] = (((u64b_t) src[n  ])      ) +
                   (((u64b_t) src[n+1]) <<  8) +
                   (((u64b_t) src[n+2]) << 16) +
                   (((u64b_t) src[n+3]) << 24) +
                   (((u64b_t) src[n+4]) << 32) +
                   (((u64b_t) src[n+5]) << 40) +
                   (((u64b_t) src[n+6]) << 48) +
                   (((u64b_t) src[n+7]) << 56) ;
}
#else  /* fast versions for little endian platforms */
#define WORDS_TO_BYTES(dst08, src64, bCnt) memcpy(dst08, src64, bCnt)
#define BYTES_TO_WORDS(dst64, src08, wCnt) memcpy(dst64, src08, 8*(wCnt))
#endif

