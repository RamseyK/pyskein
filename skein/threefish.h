/*
    threefish.h
    Copyright 2008, 2009, 2010, 2013 Hagen Fürstenau <hagen@zhuliguan.net>
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


/* 8-bit and 64-bit number types for Threefish and Skein */

typedef unsigned char u08b_t;             /*  8-bit unsigned integer */
typedef PY_UINT64_T   u64b_t;             /* 64-bit unsigned integer */

/*
 * Public interface
 *
 * Threefish is the tweakable block cipher at the heart of Skein.  It uses
 * an ARX (Add-Rotate-XOR) design: no S-boxes, purely 64-bit word operations,
 * so it maps efficiently to modern 64-bit hardware.
 *
 * The three variants differ only in word count and round count:
 *   Threefish-256:   4 words,  9 groups × 8 rounds = 72 rounds
 *   Threefish-512:   8 words,  9 groups × 8 rounds = 72 rounds
 *   Threefish-1024: 16 words, 10 groups × 8 rounds = 80 rounds
 *
 * The `feed` flag selects between two modes:
 *   feed=0  plain block cipher  (used by the standalone threefish Python object)
 *   feed=1  UBI compression     (used internally by Skein: output = E(m) XOR m,
 *                                the Matyas-Meyer-Oseas feed-forward construction
 *                                that turns Threefish into a one-way function)
 */

/* public interface */

void Threefish_256_encrypt(const u64b_t *key, const u64b_t *tweak, const u64b_t *w, u64b_t *out, int feed);
void Threefish_512_encrypt(const u64b_t *key, const u64b_t *tweak, const u64b_t *w, u64b_t *out, int feed);
void Threefish_1024_encrypt(const u64b_t *key, const u64b_t *tweak, const u64b_t *w, u64b_t *out, int feed);

void Threefish_256_decrypt(const u64b_t *key, const u64b_t *tweak, const u64b_t *w, u64b_t *out);
void Threefish_512_decrypt(const u64b_t *key, const u64b_t *tweak, const u64b_t *w, u64b_t *out);
void Threefish_1024_decrypt(const u64b_t *key, const u64b_t *tweak, const u64b_t *w, u64b_t *out);


/*
 * Rotation constants
 *
 * These bit-rotation amounts are the result of the Skein designers'
 * exhaustive search for values that maximise the minimum number of active
 * S-boxes (MDS bound) across all 8 rounds of a group.  Different amounts
 * are used for each of the 8 round positions within a group to prevent
 * slide attacks; they repeat with the 8-round period.
 */

enum {
    /* Threefish-256 */
    R_256_0_0=14, R_256_0_1=16,
    R_256_1_0=52, R_256_1_1=57,
    R_256_2_0=23, R_256_2_1=40,
    R_256_3_0=5, R_256_3_1=37,
    R_256_4_0=25, R_256_4_1=33,
    R_256_5_0=46, R_256_5_1=12,
    R_256_6_0=58, R_256_6_1=22,
    R_256_7_0=32, R_256_7_1=32,

    /* Threefish-512 */
    R_512_0_0=46, R_512_0_1=36, R_512_0_2=19, R_512_0_3=37,
    R_512_1_0=33, R_512_1_1=27, R_512_1_2=14, R_512_1_3=42,
    R_512_2_0=17, R_512_2_1=49, R_512_2_2=36, R_512_2_3=39,
    R_512_3_0=44, R_512_3_1=9, R_512_3_2=54, R_512_3_3=56,
    R_512_4_0=39, R_512_4_1=30, R_512_4_2=34, R_512_4_3=24,
    R_512_5_0=13, R_512_5_1=50, R_512_5_2=10, R_512_5_3=17,
    R_512_6_0=25, R_512_6_1=29, R_512_6_2=39, R_512_6_3=43,
    R_512_7_0=8, R_512_7_1=35, R_512_7_2=56, R_512_7_3=22,

    /* Threefish-1024 */
    R_1024_0_0=24, R_1024_0_1=13, R_1024_0_2=8, R_1024_0_3=47,
    R_1024_0_4=8, R_1024_0_5=17, R_1024_0_6=22, R_1024_0_7=37,
    R_1024_1_0=38, R_1024_1_1=19, R_1024_1_2=10, R_1024_1_3=55,
    R_1024_1_4=49, R_1024_1_5=18, R_1024_1_6=23, R_1024_1_7=52,
    R_1024_2_0=33, R_1024_2_1=4, R_1024_2_2=51, R_1024_2_3=13,
    R_1024_2_4=34, R_1024_2_5=41, R_1024_2_6=59, R_1024_2_7=17,
    R_1024_3_0=5, R_1024_3_1=20, R_1024_3_2=48, R_1024_3_3=41,
    R_1024_3_4=47, R_1024_3_5=28, R_1024_3_6=16, R_1024_3_7=25,
    R_1024_4_0=41, R_1024_4_1=9, R_1024_4_2=37, R_1024_4_3=31,
    R_1024_4_4=12, R_1024_4_5=47, R_1024_4_6=44, R_1024_4_7=30,
    R_1024_5_0=16, R_1024_5_1=34, R_1024_5_2=56, R_1024_5_3=51,
    R_1024_5_4=4, R_1024_5_5=53, R_1024_5_6=42, R_1024_5_7=41,
    R_1024_6_0=31, R_1024_6_1=44, R_1024_6_2=47, R_1024_6_3=46,
    R_1024_6_4=19, R_1024_6_5=42, R_1024_6_6=44, R_1024_6_7=25,
    R_1024_7_0=9, R_1024_7_1=48, R_1024_7_2=35, R_1024_7_3=52,
    R_1024_7_4=23, R_1024_7_5=31, R_1024_7_6=37, R_1024_7_7=20
};


/*
 * Abbreviations
 *
 * The key-schedule array kw[] is laid out as:
 *   kw[0]   = T0  (tweak word 0)
 *   kw[1]   = T1  (tweak word 1)
 *   kw[2]   = T2 = T0^T1  (extended tweak parity; precomputed so the key
 *                           injection macro can cycle through all 3 tweak words
 *                           with a simple modulo-3 rotation)
 *   kw[3]   = k0  (first key word)
 *   ...
 *   kw[3+N-1] = k_{N-1}
 *   kw[3+N]   = k_N = SKEIN_KS_PARITY ^ k0 ^ ... ^ k_{N-1}
 *                     (extra key word ensuring the key injections are all
 *                      distinct; its value is fixed by the parity constraint)
 *
 * ts points to kw[0] for tweak access; ks points to kw[3] for key access.
 */
#define ks (kw+3)
#define ts (kw)

/* 64-bit left/right rotations — the "R" in ARX */
#define RotL_64(x, N) (((x)<<(N))|((x)>>(64-(N))))
#define RotR_64(x, N) (((x)>>(N))|((x)<<(64-(N))))


/*
 * Threefish-256 rounds
 *
 * R256: one MIX step on a pair of 64-bit words.
 *   step 1  X_even += X_odd          (add: mixes the two words)
 *   step 2  X_odd   = RotL(X_odd, r) (rotate: prevents slide attacks)
 *   step 3  X_odd  ^= X_even         (XOR: finalises the diffusion)
 * This ARX pattern gives full 64-bit diffusion in two operations per pair.
 * Each R256 call operates on two independent pairs simultaneously.
 *
 * I256: key injection after every 4 rounds (i.e., twice per 8-round group).
 * The key words are rotated cyclically so each injection uses a different
 * subkey.  The tweak is injected only into words 1 and 2 (spec §2.2.2).
 * The last word also receives the subkey injection counter (R)+1, binding
 * every injection to its position in the sequence and preventing related-key
 * attacks.
 *
 * R256_8_rounds: one complete 8-round group.  The word permutation alternates
 * between (0,1,2,3) and (0,3,2,1) MIX pairings to spread diffusion across
 * all word pairs over the course of multiple rounds.
 */

#define R256(p0, p1, p2, p3, ROT)                                    \
    X##p0 += X##p1; X##p1 = RotL_64(X##p1, ROT##_0); X##p1 ^= X##p0; \
    X##p2 += X##p3; X##p3 = RotL_64(X##p3, ROT##_1); X##p3 ^= X##p2;

#define I256(R)                          \
    X0 += key[((R)+1)%5];                 \
    X1 += key[((R)+2)%5] + tweak[((R)+1)%3]; \
    X2 += key[((R)+3)%5] + tweak[((R)+2)%3]; \
    X3 += key[((R)+4)%5] + (R)+1;

#define R256_8_rounds(R)       \
    R256(0, 1, 2, 3, R_256_0); \
    R256(0, 3, 2, 1, R_256_1); \
    R256(0, 1, 2, 3, R_256_2); \
    R256(0, 3, 2, 1, R_256_3); \
    I256(2*(R));               \
    R256(0, 1, 2, 3, R_256_4); \
    R256(0, 3, 2, 1, R_256_5); \
    R256(0, 1, 2, 3, R_256_6); \
    R256(0, 3, 2, 1, R_256_7); \
    I256(2*(R)+1);

/* Inverse MIX: undo XOR then undo the rotated-add (subtract after un-rotate) */
#define INV_R256(p0, p1, p2, p3, ROT)                      \
    X##p1 = RotR_64(X##p0^X##p1, ROT##_0); X##p0 -= X##p1; \
    X##p3 = RotR_64(X##p2^X##p3, ROT##_1); X##p2 -= X##p3;

/* Inverse key injection: subtract the same subkeys that were added */
#define INV_I256(R)                      \
    X0 -= key[((R)+1)%5];                 \
    X1 -= key[((R)+2)%5] + tweak[((R)+1)%3]; \
    X2 -= key[((R)+3)%5] + tweak[((R)+2)%3]; \
    X3 -= key[((R)+4)%5] + (R)+1;

#define INV_R256_8_rounds(R)       \
    INV_I256(2*(R)+1);             \
    INV_R256(0, 3, 2, 1, R_256_7); \
    INV_R256(0, 1, 2, 3, R_256_6); \
    INV_R256(0, 3, 2, 1, R_256_5); \
    INV_R256(0, 1, 2, 3, R_256_4); \
    INV_I256(2*(R));               \
    INV_R256(0, 3, 2, 1, R_256_3); \
    INV_R256(0, 1, 2, 3, R_256_2); \
    INV_R256(0, 3, 2, 1, R_256_1); \
    INV_R256(0, 1, 2, 3, R_256_0);


/*
 * Threefish-512 rounds
 *
 * Same ARX structure as -256, scaled to 8 words (4 MIX pairs per round).
 * The word permutation changes each round to ensure every word pair is
 * mixed within one 8-round group.
 *
 * Tweak is injected into words N-3 and N-2 (words 5 and 6 for N=8),
 * matching the spec's requirement that tweak words go into the last few
 * non-terminal words.
 */

#define R512(p0, p1, p2, p3, p4, p5, p6, p7, ROT)                    \
    X##p0 += X##p1; X##p1 = RotL_64(X##p1, ROT##_0); X##p1 ^= X##p0; \
    X##p2 += X##p3; X##p3 = RotL_64(X##p3, ROT##_1); X##p3 ^= X##p2; \
    X##p4 += X##p5; X##p5 = RotL_64(X##p5, ROT##_2); X##p5 ^= X##p4; \
    X##p6 += X##p7; X##p7 = RotL_64(X##p7, ROT##_3); X##p7 ^= X##p6;

#define I512(R)                          \
    X0 += key[((R)+1)%9];                 \
    X1 += key[((R)+2)%9];                 \
    X2 += key[((R)+3)%9];                 \
    X3 += key[((R)+4)%9];                 \
    X4 += key[((R)+5)%9];                 \
    X5 += key[((R)+6)%9] + tweak[((R)+1)%3]; \
    X6 += key[((R)+7)%9] + tweak[((R)+2)%3]; \
    X7 += key[((R)+8)%9] + (R)+1;

#define R512_8_rounds(R)                   \
    R512(0, 1, 2, 3, 4, 5, 6, 7, R_512_0); \
    R512(2, 1, 4, 7, 6, 5, 0, 3, R_512_1); \
    R512(4, 1, 6, 3, 0, 5, 2, 7, R_512_2); \
    R512(6, 1, 0, 7, 2, 5, 4, 3, R_512_3); \
    I512(2*(R));                           \
    R512(0, 1, 2, 3, 4, 5, 6, 7, R_512_4); \
    R512(2, 1, 4, 7, 6, 5, 0, 3, R_512_5); \
    R512(4, 1, 6, 3, 0, 5, 2, 7, R_512_6); \
    R512(6, 1, 0, 7, 2, 5, 4, 3, R_512_7); \
    I512(2*(R)+1);

#define INV_R512(p0, p1, p2, p3, p4, p5, p6, p7, ROT)      \
    X##p1 = RotR_64(X##p0^X##p1, ROT##_0); X##p0 -= X##p1; \
    X##p3 = RotR_64(X##p2^X##p3, ROT##_1); X##p2 -= X##p3; \
    X##p5 = RotR_64(X##p4^X##p5, ROT##_2); X##p4 -= X##p5; \
    X##p7 = RotR_64(X##p6^X##p7, ROT##_3); X##p6 -= X##p7;

#define INV_I512(R)                      \
    X0 -= key[((R)+1)%9];                 \
    X1 -= key[((R)+2)%9];                 \
    X2 -= key[((R)+3)%9];                 \
    X3 -= key[((R)+4)%9];                 \
    X4 -= key[((R)+5)%9];                 \
    X5 -= key[((R)+6)%9] + tweak[((R)+1)%3]; \
    X6 -= key[((R)+7)%9] + tweak[((R)+2)%3]; \
    X7 -= key[((R)+8)%9] + (R)+1;

#define INV_R512_8_rounds(R)                   \
    INV_I512(2*(R)+1);                         \
    INV_R512(6, 1, 0, 7, 2, 5, 4, 3, R_512_7); \
    INV_R512(4, 1, 6, 3, 0, 5, 2, 7, R_512_6); \
    INV_R512(2, 1, 4, 7, 6, 5, 0, 3, R_512_5); \
    INV_R512(0, 1, 2, 3, 4, 5, 6, 7, R_512_4); \
    INV_I512(2*(R));                           \
    INV_R512(6, 1, 0, 7, 2, 5, 4, 3, R_512_3); \
    INV_R512(4, 1, 6, 3, 0, 5, 2, 7, R_512_2); \
    INV_R512(2, 1, 4, 7, 6, 5, 0, 3, R_512_1); \
    INV_R512(0, 1, 2, 3, 4, 5, 6, 7, R_512_0);


/*
 * Threefish-1024 rounds
 *
 * 16 words, 10 groups × 8 rounds = 80 rounds (more rounds than -256/-512
 * because larger states need more mixing for equivalent security).
 * Tweak words go into positions N-3=13 and N-2=14.
 */

#define R1024(p0, p1, p2, p3, p4, p5, p6, p7,                        \
              p8, p9, pA, pB, pC, pD, pE, pF, ROT)                   \
    X##p0 += X##p1; X##p1 = RotL_64(X##p1, ROT##_0); X##p1 ^= X##p0; \
    X##p2 += X##p3; X##p3 = RotL_64(X##p3, ROT##_1); X##p3 ^= X##p2; \
    X##p4 += X##p5; X##p5 = RotL_64(X##p5, ROT##_2); X##p5 ^= X##p4; \
    X##p6 += X##p7; X##p7 = RotL_64(X##p7, ROT##_3); X##p7 ^= X##p6; \
    X##p8 += X##p9; X##p9 = RotL_64(X##p9, ROT##_4); X##p9 ^= X##p8; \
    X##pA += X##pB; X##pB = RotL_64(X##pB, ROT##_5); X##pB ^= X##pA; \
    X##pC += X##pD; X##pD = RotL_64(X##pD, ROT##_6); X##pD ^= X##pC; \
    X##pE += X##pF; X##pF = RotL_64(X##pF, ROT##_7); X##pF ^= X##pE;

#define I1024(R)                           \
    X0 += key[((R)+1)%17];                  \
    X1 += key[((R)+2)%17];                  \
    X2 += key[((R)+3)%17];                  \
    X3 += key[((R)+4)%17];                  \
    X4 += key[((R)+5)%17];                  \
    X5 += key[((R)+6)%17];                  \
    X6 += key[((R)+7)%17];                  \
    X7 += key[((R)+8)%17];                  \
    X8 += key[((R)+9)%17];                  \
    X9 += key[((R)+10)%17];                 \
    XA += key[((R)+11)%17];                 \
    XB += key[((R)+12)%17];                 \
    XC += key[((R)+13)%17];                 \
    XD += key[((R)+14)%17] + tweak[((R)+1)%3]; \
    XE += key[((R)+15)%17] + tweak[((R)+2)%3]; \
    XF += key[((R)+16)%17] + (R)+1;

#define R1024_8_rounds(R)                                            \
    R1024(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F, R_1024_0); \
    R1024(0, 9, 2, D, 6, B, 4, F, A, 7, C, 3, E, 5, 8, 1, R_1024_1); \
    R1024(0, 7, 2, 5, 4, 3, 6, 1, C, F, E, D, 8, B, A, 9, R_1024_2); \
    R1024(0, F, 2, B, 6, D, 4, 9, E, 1, 8, 5, A, 3, C, 7, R_1024_3); \
    I1024(2*(R));                                                    \
    R1024(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F, R_1024_4); \
    R1024(0, 9, 2, D, 6, B, 4, F, A, 7, C, 3, E, 5, 8, 1, R_1024_5); \
    R1024(0, 7, 2, 5, 4, 3, 6, 1, C, F, E, D, 8, B, A, 9, R_1024_6); \
    R1024(0, F, 2, B, 6, D, 4, 9, E, 1, 8, 5, A, 3, C, 7, R_1024_7); \
    I1024(2*(R)+1);

#define INV_R1024(p0, p1, p2, p3, p4, p5, p6, p7,          \
                  p8, p9, pA, pB, pC, pD, pE, pF, ROT)     \
    X##p1 = RotR_64(X##p0^X##p1, ROT##_0); X##p0 -= X##p1; \
    X##p3 = RotR_64(X##p2^X##p3, ROT##_1); X##p2 -= X##p3; \
    X##p5 = RotR_64(X##p4^X##p5, ROT##_2); X##p4 -= X##p5; \
    X##p7 = RotR_64(X##p6^X##p7, ROT##_3); X##p6 -= X##p7; \
    X##p9 = RotR_64(X##p8^X##p9, ROT##_4); X##p8 -= X##p9; \
    X##pB = RotR_64(X##pA^X##pB, ROT##_5); X##pA -= X##pB; \
    X##pD = RotR_64(X##pC^X##pD, ROT##_6); X##pC -= X##pD; \
    X##pF = RotR_64(X##pE^X##pF, ROT##_7); X##pE -= X##pF;

#define INV_I1024(R)                       \
    X0 -= key[((R)+1)%17];                  \
    X1 -= key[((R)+2)%17];                  \
    X2 -= key[((R)+3)%17];                  \
    X3 -= key[((R)+4)%17];                  \
    X4 -= key[((R)+5)%17];                  \
    X5 -= key[((R)+6)%17];                  \
    X6 -= key[((R)+7)%17];                  \
    X7 -= key[((R)+8)%17];                  \
    X8 -= key[((R)+9)%17];                  \
    X9 -= key[((R)+10)%17];                 \
    XA -= key[((R)+11)%17];                 \
    XB -= key[((R)+12)%17];                 \
    XC -= key[((R)+13)%17];                 \
    XD -= key[((R)+14)%17] + tweak[((R)+1)%3]; \
    XE -= key[((R)+15)%17] + tweak[((R)+2)%3]; \
    XF -= key[((R)+16)%17] + (R)+1;

#define INV_R1024_8_rounds(R)                                            \
    INV_I1024(2*(R)+1);                                                  \
    INV_R1024(0, F, 2, B, 6, D, 4, 9, E, 1, 8, 5, A, 3, C, 7, R_1024_7); \
    INV_R1024(0, 7, 2, 5, 4, 3, 6, 1, C, F, E, D, 8, B, A, 9, R_1024_6); \
    INV_R1024(0, 9, 2, D, 6, B, 4, F, A, 7, C, 3, E, 5, 8, 1, R_1024_5); \
    INV_R1024(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F, R_1024_4); \
    INV_I1024(2*(R));                                                    \
    INV_R1024(0, F, 2, B, 6, D, 4, 9, E, 1, 8, 5, A, 3, C, 7, R_1024_3); \
    INV_R1024(0, 7, 2, 5, 4, 3, 6, 1, C, F, E, D, 8, B, A, 9, R_1024_2); \
    INV_R1024(0, 9, 2, D, 6, B, 4, F, A, 7, C, 3, E, 5, 8, 1, R_1024_1); \
    INV_R1024(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F, R_1024_0);

