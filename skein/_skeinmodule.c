/*
    _skeinmodule.c
    Copyright 2008, 2009, 2010, 2012, 2013 Hagen Fürstenau <hagen@zhuliguan.net>
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

#include "Python.h"
#include "pythread.h"
#include "threefish.h"
#include "_skeinmodule.h"


skeinObject *
new_skein_object(void)
{
    skeinObject *new_obj = NULL;

    /* Set next_tree_level right away, so that we have a valid pointer in
       skein_dealloc in any case. */
    if ((new_obj=PyObject_New(skeinObject, &skeinType)) != NULL) {
        new_obj->state.block_processor = NULL;
        new_obj->state.next_tree_level = NULL;
#ifdef Py_GIL_DISABLED
        new_obj->lock = (PyMutex){0};
#endif
    }
    return new_obj;
}


/* helper function to get tree parameters out of Python sequence */

u08b_t get_tree_param(PyObject *seq, Py_ssize_t i, long min, long max)
{
    PyObject *item = NULL;
    int overflow = 0;
    long v = 0;

    item = PySequence_Fast_GET_ITEM(seq, i);
    if (PyFloat_Check(item))
        goto type_error;  /* otherwise it would get silently converted */
    v = PyLong_AsLongAndOverflow(item, &overflow);
    /* If v == -1, there's a TypeError (which we overwrite)
       or an Overflow, which can take the same path as v < min */
    if (v == -1 && PyErr_Occurred())
        goto type_error;
    if (v < min || v > max)
        goto value_error;
    return v;

type_error:
    PyErr_Format(PyExc_TypeError, "tree parameters have to be integers");
    return 0;
value_error:
    PyErr_Format(PyExc_ValueError, "tree parameters have to be between "
                 "(1, 1, 2) and (56, 56, 255)");
    return 0;
}


/* hash object attributes */

static PyObject *
skein_get_name(const skeinObject *self, void *closure)
{
    char name[11] = {0};

    snprintf(name, sizeof(name), "Skein-%d", self->stateBytes*8);
    return PyUnicode_FromString(name);
}

static PyObject *
skein_get_block_size(const skeinObject *self, void *closure)
{
    return PyLong_FromLong(self->stateBytes);
}

static PyObject *
skein_get_block_bits(const skeinObject *self, void *closure)
{
    return PyLong_FromLong(self->stateBytes*8);
}

static PyObject *
skein_get_digest_size(const skeinObject *self, void *closure)
{
    return PyLong_FromUnsignedLongLong((self->digestBits-1)/8+1);
}

static PyObject *
skein_get_digest_bits(const skeinObject *self, void *closure)
{
    return PyLong_FromUnsignedLongLong(self->digestBits);
}

static PyObject *
skein_get_hashed_bits(skeinObject *self, void *closure)
{
    PyObject *eight = NULL;
    PyObject *bytes = NULL;
    PyObject *product = NULL;
    PyObject *bits = NULL;
    PyObject *res = NULL;
    u64b_t hashed_bytes;
    u08b_t missing_bits;

    /* Snapshot mutable fields under the lock; all Python API calls happen
       outside it to avoid holding the lock during memory allocation. */
    SKEIN_LOCK(self);
    hashed_bytes = self->hashed_bytes;
    missing_bits = self->missing_bits;
    SKEIN_UNLOCK(self);

    if ((eight=PyLong_FromLong(8)) == NULL)
        return NULL;

    if ((bytes=PyLong_FromUnsignedLongLong(hashed_bytes)) == NULL)
        goto error;
    if ((bits=PyLong_FromLong(missing_bits)) == NULL)
        goto error;

    product = PyNumber_Multiply(bytes, eight);
    if (product == NULL)
        goto error;
    res = PyNumber_InPlaceSubtract(product, bits);
    if (res == NULL)
        goto error;

    Py_DECREF(eight);
    Py_DECREF(bytes);
    Py_DECREF(bits);
    Py_DECREF(product);
    return res;

error:
    Py_CLEAR(eight);
    Py_CLEAR(bytes);
    Py_CLEAR(bits);
    Py_CLEAR(product);
    return NULL;
}

static PyGetSetDef skein_getseters[] = {
    {"name", (getter)skein_get_name, NULL, NULL, NULL},
    {"block_size", (getter)skein_get_block_size, NULL, NULL, NULL},
    {"block_bits", (getter)skein_get_block_bits, NULL, NULL, NULL},
    {"digest_size", (getter)skein_get_digest_size, NULL, NULL, NULL},
    {"digest_bits", (getter)skein_get_digest_bits, NULL, NULL, NULL},
    {"hashed_bits", (getter)skein_get_hashed_bits, NULL, NULL, NULL},
    {NULL}
};


/* threefish object attributes */
static PyObject *
threefish_get_block_size(const threefishObject *self, void *closure)
{
    return PyLong_FromLong(self->blockBytes);
}

static PyObject *
threefish_get_block_bits(const threefishObject *self, void *closure)
{
    return PyLong_FromLong(self->blockBytes*8);
}

static PyObject *
threefish_get_tweak(threefishObject *self, void *closure)
{
    PyObject *rv = NULL;
    char *buf = NULL;

    rv = PyBytes_FromStringAndSize(NULL, 16);
    if (rv == NULL)
        return NULL;

    if ((buf = PyBytes_AsString(rv)) == NULL) {
        Py_DECREF(rv);
        return NULL;
    }

    SKEIN_LOCK(self);
    WORDS_TO_BYTES((u08b_t *)buf, self->kw, 16);
    SKEIN_UNLOCK(self);
    return rv;
}

static int
threefish_set_tweak(threefishObject *self, PyObject *value, void *closure)
{
    char *buf = NULL;
    Py_ssize_t len = 0;
    PyObject *h = NULL;

    if (PyByteArray_Check(value))
        if ((h = value = PyBytes_FromObject(value)) == NULL)
            return -1;
    if (PyBytes_AsStringAndSize(value, &buf, &len) < 0)
        goto error;
    if (len != 16) {
        PyErr_SetString(PyExc_ValueError, "tweak value must have 16 bytes");
        goto error;
    }
    SKEIN_LOCK(self);
    BYTES_TO_WORDS(self->kw, (u08b_t *)buf, 2);
    self->kw[2] = self->kw[0] ^ self->kw[1];  /* update extended-tweak parity (T2 = T0^T1) */
    SKEIN_UNLOCK(self);
    Py_CLEAR(h);
    return 0;
error:
    Py_CLEAR(h);
    return -1;
}

static PyGetSetDef threefish_getseters[] = {
    {"block_size", (getter)threefish_get_block_size, NULL, NULL, NULL},
    {"block_bits", (getter)threefish_get_block_bits, NULL, NULL, NULL},
    {"tweak", (getter)threefish_get_tweak, (setter)threefish_set_tweak,
     NULL, NULL},
    {NULL}
};


/* Skein Update and Result functions */

int
hash_bytes(skeinObject *sk, const u08b_t *msg, size_t msgByteCnt)
{
    size_t n = 0;
    size_t origByteCnt = msgByteCnt;  /* save before we decrement it */
    int ok = 1;

    if (msgByteCnt >= (~(u64b_t)0) - sk->hashed_bytes) {
        PyErr_SetString(PyExc_OverflowError,
                        "can't hash more than 2**64-1 bytes");
        return 0;
    }

    /* Only release the GIL for sequential hashing (pure-C block processors).
       Tree hashing uses Python memory APIs and must hold the GIL. */
    PyThreadState *_save = NULL;
    if (sk->state.next_tree_level == NULL)
        _save = PyEval_SaveThread();

    if (msgByteCnt + sk->bCnt > sk->stateBytes) { /* any full block? */
        /* fill buffer and process one block */
        if (sk->bCnt) {
            n = sk->stateBytes - sk->bCnt;  /* # bytes free in buffer b[] */
            if (n) {
                memcpy(&sk->b[sk->bCnt], msg, n);
                msgByteCnt -= n;
                msg += n;
                sk->bCnt += n;
            }
            if (!sk->state.block_processor(&sk->state,sk->b, 1,sk->stateBytes)) {
                ok = 0;
                goto done;
            }
            sk->bCnt = 0;
        }
        /* process any remaining full blocks */
        if (msgByteCnt > sk->stateBytes) {
            n = (msgByteCnt-1) / sk->stateBytes;
            if (!sk->state.block_processor(&sk->state, msg, n, sk->stateBytes)) {
                ok = 0;
                goto done;
            }
            msgByteCnt -= n * sk->stateBytes;
            msg += n * sk->stateBytes;
        }
    }
    /* remaining message data goes into buffer */
    if (msgByteCnt) {
        memcpy(&sk->b[sk->bCnt], msg, msgByteCnt);
        sk->bCnt += msgByteCnt;
    }
    sk->hashed_bytes += origByteCnt;  /* count all bytes fed, not just buffered tail */
done:
    if (_save != NULL)
        PyEval_RestoreThread(_save);
    return ok;
}

struct args_t {
    processor_t basic_processor;
    skein_state_t *state;
    size_t n;
    const u08b_t *data;
    u08b_t stateBytes;
    PyThread_type_lock lock;
};

static void
run_basic_processor(void *args_raw)
{
    struct args_t *args = (struct args_t *) args_raw;

    args->basic_processor(args->state, args->data, args->n, args->stateBytes);
    PyThread_release_lock(args->lock);
}

int
tree_block_processor(skein_state_t *state,
                     const u08b_t *data, size_t count, u08b_t stateBytes)
{
    skein_state_t *next_level = state->next_tree_level;
    skein_state_t *last_level = NULL;
    skein_state_t *state2 = NULL;
    processor_t basic_processor = next_level->block_processor;
    size_t n = state->remaining_tree_blocks;
    u08b_t w[SKEIN_MAX_BLOCK_BYTES] = {0};
    u08b_t remaining_levels = state->remaining_tree_levels;
    struct args_t *args = NULL;

    if (remaining_levels == 0) {  /* we do not have to care about nodes */
        basic_processor(state, data, count, stateBytes);
    } else if (count < n) {  /* data fits into this node */
        basic_processor(state, data, count, stateBytes);
        state->remaining_tree_blocks -= count;
    } else {
        for (last_level = next_level;
             last_level->next_tree_level;
             last_level = last_level->next_tree_level);

        /* fill the current node except for the last block */
        if (n > 1) {
            basic_processor(state, data, n-1, stateBytes);
            count -= n-1;
            data += (n-1)*stateBytes;
        }

        /* hash all complete blocks */
        while (count) {
            /* hash the last block */
            state->T[1] |= SKEIN_T1_FLAG_FINAL;
            basic_processor(state, data, 1, stateBytes);
            --count;
            data += stateBytes;
            if (state2) {
                PyThread_acquire_lock(args->lock, 1);
                state2->T[1] |= SKEIN_T1_FLAG_FINAL;
                data += n*stateBytes;  /* this was left out below */
                basic_processor(state2, data, 1, stateBytes);
                --count;
                data += stateBytes;
                PyThread_release_lock(args->lock);

                /* tweak correction */
                state->T[0] += state->tree_blocks*stateBytes;
            }

            /* If next_level is the end of the list, make a new level state. */
            if (next_level == last_level) {
                /* The new state is inserted before the last one, so that
                   last_level pointers stay valid. */
                state->next_tree_level = PyMem_Calloc(1, sizeof(skein_state_t));
                if (state->next_tree_level == NULL) {
                    PyErr_SetNone(PyExc_MemoryError);
                    return 0;
                }
                state->next_tree_level->next_tree_level = next_level;
                next_level = state->next_tree_level;

                /* init the new state from last_level */
                memcpy(next_level->X, last_level->X, sizeof(next_level->X));
                next_level->T[0] = 0;
                next_level->T[1] = ((state->T[1]
                                        + ((u64b_t)1 << SKEIN_T1_POS_LEVEL))
                                        & ~SKEIN_T1_FLAG_FINAL)
                                        | SKEIN_T1_FLAG_FIRST;
                next_level->block_processor = last_level->block_processor;
                next_level->tree_blocks = next_level->remaining_tree_blocks
                                        = last_level->tree_blocks;
                next_level->remaining_tree_levels = remaining_levels - 1;
            }

            /* push result up to next level */
            WORDS_TO_BYTES(w, state->X, stateBytes);
            tree_block_processor(next_level, w, 1, stateBytes);
            if (state2) {
                WORDS_TO_BYTES(w, state2->X, stateBytes);
                tree_block_processor(next_level, w, 1, stateBytes);
            }

            /* reset state by cloning the last level */
            memcpy(state->X, last_level->X, sizeof(state->X));
            state->T[1] |= SKEIN_T1_FLAG_FIRST;
            state->T[1] &= ~SKEIN_T1_FLAG_FINAL;

            n = state->tree_blocks-1;
            if (count < n) {
                n = count;
                if (count == 0)  /* guard basic_processor below */
                    break;
            }

            /* if there are enough blocks, prepare a second state */
            if (count > 2*n+1) {  /* i.e. >= 2*tree_blocks */
                if (state2 == NULL) {
                    state2 = PyMem_Malloc(sizeof(skein_state_t));
                    if (state2 == NULL) {
                        PyErr_SetNone(PyExc_MemoryError);
                        return 0;
                    }
                    args = PyMem_Malloc(sizeof(struct args_t));
                    if (args == NULL) {
                        PyMem_Free(state2);
                        PyErr_SetNone(PyExc_MemoryError);
                        return 0;
                    }
                    args->basic_processor = basic_processor;
                    args->state = state2;
                    args->n = state->tree_blocks-1;
                    args->stateBytes = stateBytes;
                    args->lock = PyThread_allocate_lock();
                    if (args->lock == NULL) {
                        PyMem_Free(state2);
                        PyMem_Free(args);
                        PyErr_SetString(PyExc_RuntimeError,
                                        "can't allocate lock");
                        return 0;
                    }
                }
                memcpy(state2->X, state->X, sizeof(state2->X));
                state2->T[0] = state->T[0] + state->tree_blocks*stateBytes;
                state2->T[1] = state->T[1];
            } else {
                if (state2 != NULL) {
                    PyMem_Free(state2);
                    PyThread_acquire_lock(args->lock, 0);
                    PyThread_release_lock(args->lock);
                    PyThread_free_lock(args->lock);
                    PyMem_Free(args);
                }
                state2 = NULL;
            }

            /* hash next n blocks in new thread if possible */
            if (state2) {
                args->data = data + (n+1)*stateBytes;
                PyThread_acquire_lock(args->lock, 1);
                PyThread_start_new_thread(run_basic_processor, args);
                count -= n;
                /* "data" is incremented in the next loop iteration, when
                   hashing the last block (we're guaranteed to have another
                   iteration). */
            }

            /* hash n blocks */
            basic_processor(state, data, n, stateBytes);
            count -= n;
            data += n*stateBytes;
        }

        /* incomplete node */
        state->remaining_tree_blocks = state->tree_blocks - n;
    }
    return 1;
}


void
finalize_tree(skein_state_t *state, skein_state_t *target_state,
              u08b_t stateBytes)
{
    skein_state_t *next_level = state->next_tree_level;
    processor_t basic_processor = next_level->block_processor;
    skein_state_t saved_state = {0};
    u08b_t w[SKEIN_MAX_BLOCK_BYTES] = {0};

    if (next_level->next_tree_level != NULL) {
        saved_state = *next_level;
        next_level->T[1] |= SKEIN_T1_FLAG_FINAL;
        WORDS_TO_BYTES(w, state->X, stateBytes);
        basic_processor(next_level, w, 1, stateBytes);
        finalize_tree(next_level, target_state, stateBytes);
        *next_level = saved_state;
    } else  /* "state" is highest tree level */
        *target_state = *state;
}

/*
 * output_hash — generate digest bytes [start, stop) from a finalised state.
 *
 * Skein uses an "output transformation" (spec §2.3) to turn the final chaining
 * value into an arbitrarily long output stream.  The construction is:
 *
 *   for counter i = 0, 1, 2, …:
 *       output_block_i = UBI(final_state, i, type=OUT)
 *
 * Each 8-byte counter value is compressed independently with the FIRST|FINAL
 * type-OUT tweak, using the message-phase final chaining value as the key.
 * Because each call uses a distinct counter-based tweak, the output blocks are
 * independent, which gives Skein XOF (extendable output function) behaviour.
 *
 * The state is saved before finalisation and restored afterward so that
 * digest() can be called multiple times on the same hash object without
 * advancing its position (non-destructive output).
 */
void
output_hash(skeinObject *sk, u08b_t *hashVal, u64b_t start, u64b_t stop)
{
    u64b_t        n = 0;
    u64b_t        offset=0;
    u64b_t        X[SKEIN_MAX_STATE_WORDS] = {0};
    skein_state_t saved_state = {0};
    u08b_t        saved_b[SKEIN_MAX_BLOCK_BYTES] = {0};
    u08b_t        shift = 0;

    /* save X and b so digest() is non-destructive */
    saved_state = sk->state;
    memcpy(saved_b, sk->b, sizeof(saved_b));

    /* finalise message processing (sets FINAL flag, zero-pads, compresses) */
    if (sk->state.next_tree_level == NULL)
        HASH_FINALIZE(sk)
    else {
        /* for tree hashing, switch to the basic processor then propagate up */
        sk->state.block_processor = sk->state.next_tree_level->block_processor;
        HASH_FINALIZE(sk);
        finalize_tree(&sk->state, &sk->state, sk->stateBytes);
    }

    /* counter-mode output: encrypt each 8-byte counter with the final state as
       key.  X holds the final chaining value and is reloaded before each block
       so every counter block is encrypted with the same key independently. */
    memcpy(X, sk->state.X, sizeof(X)); /* keep a local copy */
    memset(sk->b, 0, sizeof(sk->b));   /* buffer for output counter */
    shift = start%sk->stateBytes;
    for (u64b_t i = start/sk->stateBytes; i<=(stop-1)/sk->stateBytes; ++i) {
        WORDS_TO_BYTES(sk->b, &i, 4);
        HASH_BLOCK(sk, sk->b, 8, OUT);
        n = stop-i*sk->stateBytes;
        if (n > sk->stateBytes)
            n = sk->stateBytes;
        if (shift) {
            /* first block: copy only the bytes within [start, …) */
            WORDS_TO_BYTES(sk->b, sk->state.X, n);
            memcpy(hashVal, sk->b+shift, n-shift);
            memset(sk->b, 0, sizeof(sk->b));   /* clear buffer again */
            offset = n-shift;
            shift = 0;
        } else {
            WORDS_TO_BYTES(hashVal+offset, sk->state.X, n);
            offset += n;
        }
        memcpy(sk->state.X, X, sizeof(X)); /* restore counter-mode key */
    }
    /* if digest_bits is not a multiple of 8, zero the unused low bits of the
       last byte to match the spec's bit-oriented output convention */
    if (8*stop > sk->digestBits) {
        n = 8*stop - sk->digestBits;       /* number of bits to clear */
        hashVal[offset-1] &= ~((1U<<n)-1);
    }

    /* restore X, b and (for tree hashing) block_processor */
    sk->state = saved_state;
    memcpy(sk->b, saved_b, sizeof(sk->b));
    if (sk->state.next_tree_level != NULL)
        sk->state.block_processor = &tree_block_processor;
    return;

error:  assert(0);
}


/*
 * Skein block hashing functions (UBI compression)
 *
 * Each function implements one UBI call's inner loop.  The loop processes
 * `count` full blocks of `increment` bytes each.
 *
 * Per-block operations:
 *
 *   T[0] += increment
 *     T[0] is the cumulative byte-position counter (spec §2.2.1).  Adding the
 *     block size makes every block's tweak (T[0], T[1]) unique within the call,
 *     which is the core property that gives UBI its security proof.
 *
 *   T[2] = T[0] ^ T[1]
 *     Threefish uses 3 internal tweak words but the state stores only T[0] and
 *     T[1].  T[2] = T[0]^T[1] is the "extended tweak parity" (spec §2.2.1),
 *     recomputed here so the key-injection macro (I256/I512/I1024) can rotate
 *     through all three tweak words with a simple modulo-3 index.
 *
 *   X[N] = X[0]^...^X[N-1] ^ SKEIN_KS_PARITY
 *     Threefish's key schedule needs N+1 words but only N are the actual
 *     chaining value.  The (N+1)th word is derived from the XOR of all N
 *     chaining words plus the C240 parity constant (spec §2.2.4).  This
 *     ensures every subkey injection uses a distinct value, breaking the
 *     symmetry that would otherwise permit related-key attacks.
 *
 *   Threefish_*_encrypt(X, T, w, X, 1)
 *     Called with feed=1 (UBI mode): output = E_K(m) XOR m, where K=X
 *     (chaining value used as Threefish key).  The result replaces X in-place,
 *     becoming the new chaining value.  This feed-forward construction ensures
 *     the compression is one-way.
 *
 *   T[1] &= ~SKEIN_T1_FLAG_FIRST
 *     Clear the FIRST flag after the first block so subsequent blocks in the
 *     same UBI call are not incorrectly tagged as first blocks.
 */

int
Skein_256_Process_Block(skein_state_t *state,
                        const u08b_t *data, size_t count,
                        u08b_t increment)
{
    enum {
        WCNT = SKEIN_256_STATE_WORDS
    };
    u64b_t w[WCNT] = {0};
    u64b_t *X = state->X;
    u64b_t *T = state->T;

    do {
        /* this implementation only supports 2**64 input bytes
           (no carry out here) */
        T[0] += increment;
        T[2] = T[0] ^ T[1];

        /* compute the (N+1)th key schedule word from the parity constraint */
        X[4] = X[0] ^ X[1] ^ X[2] ^ X[3] ^ SKEIN_KS_PARITY;

        /* UBI compression: convert block to words and run Threefish feed-forward */
        BYTES_TO_WORDS(w, data, WCNT);
        Threefish_256_encrypt(X, T, w, X, 1);

        T[1] &= ~SKEIN_T1_FLAG_FIRST;
        data += SKEIN_256_BLOCK_BYTES;
    } while (--count);
    return 1;
}

int
Skein_512_Process_Block(skein_state_t *state,
                        const u08b_t *data, size_t count,
                        u08b_t increment)
{
    enum {
        WCNT = SKEIN_512_STATE_WORDS
    };

    u64b_t w[WCNT] = {0};
    u64b_t *X = state->X;
    u64b_t *T = state->T;

    do {
        /* this implementation only supports 2**64 input bytes
           (no carry out here) */
        T[0] += increment;
        T[2] = T[0] ^ T[1];

        /* compute the (N+1)th key schedule word from the parity constraint */
        X[8] = X[0] ^ X[1] ^ X[2] ^ X[3] ^
               X[4] ^ X[5] ^ X[6] ^ X[7] ^ SKEIN_KS_PARITY;

        /* UBI compression: convert block to words and run Threefish feed-forward */
        BYTES_TO_WORDS(w, data, WCNT);
        Threefish_512_encrypt(X, T, w, X, 1);

        T[1] &= ~SKEIN_T1_FLAG_FIRST;
        data += SKEIN_512_BLOCK_BYTES;
    } while (--count);
    return 1;
}

int
Skein_1024_Process_Block(skein_state_t *state,
                         const u08b_t *data, size_t count,
                         u08b_t increment)
{
    enum {
        WCNT = SKEIN_1024_STATE_WORDS
    };

    u64b_t w[WCNT] = {0};
    u64b_t *X = state->X;
    u64b_t *T = state->T;

    do {
        /* this implementation only supports 2**64 input bytes
           (no carry out here) */
        T[0] += increment;
        T[2]  = T[0] ^ T[1];

        /* compute the (N+1)th key schedule word from the parity constraint */
        X[16] = X[ 0] ^ X[ 1] ^ X[ 2] ^ X[ 3] ^
                X[ 4] ^ X[ 5] ^ X[ 6] ^ X[ 7] ^
                X[ 8] ^ X[ 9] ^ X[10] ^ X[11] ^
                X[12] ^ X[13] ^ X[14] ^ X[15] ^ SKEIN_KS_PARITY;

        /* UBI compression: convert block to words and run Threefish feed-forward */
        BYTES_TO_WORDS(w, data, WCNT);
        Threefish_1024_encrypt(X, T, w, X, 1);

        T[1] &= ~SKEIN_T1_FLAG_FIRST;
        data += SKEIN_1024_BLOCK_BYTES;
    } while (--count);
    return 1;
}

/* hash object methods */

static PyObject *
skein_getstate(skeinObject *sk)
{
    PyObject *lst = NULL;
    PyObject *item = NULL;
    PyObject *rv = NULL;
    u08b_t buf[SKEIN_MAX_BLOCK_BYTES] = {0};
    skein_state_t *state = NULL;
    Py_ssize_t i = 0;
    u64b_t x = 0;

    /* Build the state as a list (grows freely, no private _PyTuple_Resize),
       then convert to a tuple at the end. Each APPEND_NEW consumes its
       argument's reference on both success and failure paths. */
#define APPEND_NEW(expr) \
    do { \
        if ((item = (expr)) == NULL) goto fail; \
        if (PyList_Append(lst, item) < 0) { Py_DECREF(item); goto fail; } \
        Py_DECREF(item); \
    } while (0)

    if ((lst=PyList_New(0)) == NULL)
        return NULL;

    /* intro */
    APPEND_NEW(PyLong_FromLong(2)); /* protocol version */
    APPEND_NEW(PyLong_FromLong(sk->digestBits));
    APPEND_NEW(PyLong_FromLong(sk->stateBytes));
    APPEND_NEW(PyLong_FromLong(sk->hashed_bytes));
    APPEND_NEW(PyLong_FromLong(sk->missing_bits));
    APPEND_NEW(PyBytes_FromStringAndSize((char *)sk->b, sk->bCnt));

    /* X and T */
    WORDS_TO_BYTES(buf, sk->state.X, sk->stateBytes);
    APPEND_NEW(PyBytes_FromStringAndSize((char *)buf, sk->stateBytes));
    WORDS_TO_BYTES(buf, sk->state.T, 2*8);
    APPEND_NEW(PyBytes_FromStringAndSize((char *)buf, 2*8));

    /* finished for sequential hashing */
    if ((state=sk->state.next_tree_level) == NULL)
        goto done;

    /* tree intro */
    for (i=-1, x=sk->state.tree_blocks; x; i++, x >>= 1);
    APPEND_NEW(PyLong_FromLong(i));  /* log_2(tree_blocks_leaf) */
    for (i=-1, x=state->tree_blocks; x; i++, x >>= 1);
    APPEND_NEW(PyLong_FromLong(i));  /* log_2(tree_blocks_node) */
    APPEND_NEW(PyLong_FromLong(sk->state.remaining_tree_levels+1));
    WORDS_TO_BYTES(buf, &sk->state.remaining_tree_blocks, 8);
    APPEND_NEW(PyBytes_FromStringAndSize((char *)buf, 8));

    /* all tree states */
    while (1) {
        WORDS_TO_BYTES(buf, state->X, sk->stateBytes);
        APPEND_NEW(PyBytes_FromStringAndSize((char *)buf, sk->stateBytes));
        WORDS_TO_BYTES(buf, state->T, 2*8);
        APPEND_NEW(PyBytes_FromStringAndSize((char *)buf, 2*8));
        WORDS_TO_BYTES(buf, &state->remaining_tree_blocks, 8);
        APPEND_NEW(PyBytes_FromStringAndSize((char *)buf, 8));

        if ((state=state->next_tree_level) == NULL)
            break;
    }

done:
    rv = PyList_AsTuple(lst);
    Py_DECREF(lst);
    return rv;

fail:
    Py_DECREF(lst);
    return NULL;
#undef APPEND_NEW
}


int
skein_setstate(skeinObject *sk, PyObject *t)
{
    PyObject *buf = NULL;
    PyObject *seq = NULL;
    processor_t basic_processor = {0};
    Py_ssize_t len = 0;
    Py_ssize_t i = 0;
    u08b_t tree_leaf = 0;
    u08b_t tree_fan = 0;
    u08b_t tree_max = 0;
    u64b_t tree_blocks = 0;
    u64b_t remaining_levels = 0;
    u64b_t x = 0;
    size_t stateWords = 0;
    skein_state_t *state = NULL;

    /* minimum length and protocol version */
    if ((len=PyTuple_Size(t)) < 8  /* includes error code -1 */
            || PyLong_AsLong(PyTuple_GetItem(t, 0)) != 2)
        return 0;

    /* digestBits */
    sk->digestBits = PyLong_AsLong(PyTuple_GetItem(t, 1));
    if (sk->digestBits == 0 || sk->digestBits % 8 != 0)  /* also captures error code -1 */
        return 0;

    /* stateBytes */
    sk->stateBytes = PyLong_AsLong(PyTuple_GetItem(t, 2));
    stateWords = sk->stateBytes / 8;

    /* hashed_bytes and missing_bits */
    sk->hashed_bytes = PyLong_AsLongLong(PyTuple_GetItem(t, 3));
    sk->missing_bits = PyLong_AsLongLong(PyTuple_GetItem(t, 4));
    if (sk->missing_bits > 7)  /* must be in [0, 7] */
        return 0;

    /* pointer to basic processor */
    switch (sk->stateBytes) {
        case 32: basic_processor = &Skein_256_Process_Block; break;
        case 64: basic_processor = &Skein_512_Process_Block; break;
        case 128: basic_processor = &Skein_1024_Process_Block; break;
        default: return 0;
    }

    /* b and bCnt */
    buf = PyTuple_GetItem(t, 5);
    if (!PyBytes_Check(buf))
        return 0;
    if ((i=PyBytes_Size(buf)) > sk->stateBytes)
        return 0;
    memcpy(sk->b, PyBytes_AsString(buf), i);
    sk->bCnt = i;
    if (sk->missing_bits && !sk->bCnt)  /* missing_bits requires at least one buffered byte */
        return 0;

    /* X and T */
    buf = PyTuple_GetItem(t, 6);
    if (!PyBytes_Check(buf) || (PyBytes_Size(buf) != sk->stateBytes))
        return 0;
    BYTES_TO_WORDS(sk->state.X, PyBytes_AsString(buf), stateWords);
    buf = PyTuple_GetItem(t, 7);
    if (!PyBytes_Check(buf) || (PyBytes_Size(buf) != 2*8))
        return 0;
    BYTES_TO_WORDS(sk->state.T, PyBytes_AsString(buf), 2);

    /* finalize in case of sequential hashing */
    if (len == 8) {
        sk->state.block_processor = basic_processor;
        return 1;
    }

    /* tree intro */
    if (len < 15)
        return 0;
    sk->state.block_processor = &tree_block_processor;
    seq = PyTuple_GetSlice(t, 8, 11);
    if (!((tree_leaf=get_tree_param(seq, 0, 1, 56))
          && (tree_fan=get_tree_param(seq, 1, 1, 56))
          && (tree_max=get_tree_param(seq, 2, 2, 255)))) {
        Py_DECREF(seq);
        return 0;
    }
    Py_DECREF(seq);
    sk->state.tree_blocks = 1 << ((u64b_t)tree_leaf);
    tree_blocks = 1 << ((u64b_t)tree_fan);
    sk->state.remaining_tree_levels = remaining_levels = tree_max-1;
    buf = PyTuple_GetItem(t, 11);
    if (!PyBytes_Check(buf) || (PyBytes_Size(buf) != 8))
        return 0;
    BYTES_TO_WORDS(&x, PyBytes_AsString(buf), 1);
    if (x > sk->state.tree_blocks)
        return 0;
    sk->state.remaining_tree_blocks = x;

    /* build all tree levels */
    i = 12;
    state = &sk->state;
    while (1) {
        /* allocate new level */
        state->next_tree_level = PyMem_Malloc(sizeof(skein_state_t));
        if (state->next_tree_level == NULL)
            return 0;
        state = state->next_tree_level;
        state->next_tree_level = NULL;  /* termination in case of error */

        /* stock values */
        state->block_processor = basic_processor;
        state->tree_blocks = tree_blocks;
        /* remaining_levels == 0 is valid: it is the terminal "end" template
           entry that init_tree always appends after the active levels.
           Assign first, then decrement so the template gets value 0. */
        state->remaining_tree_levels = remaining_levels;

        /* values from tuple */
        buf = PyTuple_GetItem(t, i++);
        if (!PyBytes_Check(buf) || (PyBytes_Size(buf) != sk->stateBytes))
            return 0;
        BYTES_TO_WORDS(state->X, PyBytes_AsString(buf), stateWords);
        buf = PyTuple_GetItem(t, i++);
        if (!PyBytes_Check(buf) || (PyBytes_Size(buf) != 2*8))
            return 0;
        BYTES_TO_WORDS(state->T, PyBytes_AsString(buf), 2);
        buf = PyTuple_GetItem(t, i++);
        if (!PyBytes_Check(buf) || (PyBytes_Size(buf) != 8))
            return 0;
        BYTES_TO_WORDS(&x, PyBytes_AsString(buf), 1);
        if (x > tree_blocks)
            return 0;
        state->remaining_tree_blocks = x;

        if (i == len)
            break;
        if (len-i < 3)
            return 0;
        /* The template entry (remaining_levels == 0) must be the last one.
           Any additional entries would exceed tree_max. */
        if (remaining_levels == 0)
            return 0;
        remaining_levels--;
    }
    return 1;
}


static PyObject *
skein___reduce__(skeinObject *self, PyObject *args)
{
    PyObject *m = PyImport_ImportModule("_skein");
    PyObject *from_state_func = NULL;
    PyObject *t = NULL;
    PyObject *res = NULL;

    if (m == NULL)
        return NULL;
    from_state_func = PyObject_GetAttrString(m, "_from_state");
    Py_DECREF(m);
    if (from_state_func == NULL)
        return NULL;

    SKEIN_LOCK(self);
    t = skein_getstate(self);
    SKEIN_UNLOCK(self);

    if (t == NULL)
        goto error;
    res = PyTuple_Pack(1, t);
    Py_DECREF(t);
    t = res;
    if (t == NULL)
        goto error;
    res = PyTuple_Pack(2, from_state_func, t);
    Py_DECREF(t);
    Py_DECREF(from_state_func);
    return res;

error:
    Py_DECREF(from_state_func);
    return NULL;
}


static PyObject *
skein_repr(skeinObject *self)
{
    return PyUnicode_FromFormat("<Skein-%d hash object at %p>",
                                self->stateBytes*8, self);
}


PyDoc_STRVAR(skein_update__doc__,
"Update this hash object's state with the provided bytes object.");

static PyObject *
skein_update(skeinObject *self, PyObject *args, PyObject *kw)
{
    static char *kwlist[] = {"message", "bits", NULL};
    Py_ssize_t bytes = -1;
    Py_ssize_t bits = -1;
    Py_buffer buf = {0};

    if (!PyArg_ParseTupleAndKeywords(args, kw, "y*|n:update", kwlist,
                                     &buf, &bits))
        return NULL;
    if (!buf.len)
        goto finished;  /* so we don't have to worry about it any more */

    /* put number of whole bytes and remaining bits into 'bytes' and 'bits' */
    if (bits == -1) {
        bytes = buf.len;
        bits = 0;
    }
    else if (bits >= 0) {
        bytes = ((bits-1)>>3) + 1;
        if (bytes > buf.len) {
            PyErr_SetString(PyExc_ValueError,
                            "'bits' larger than 8*len(message)");
            PyBuffer_Release(&buf);
            return NULL;
        }
        bits %= 8;
        if (bits)
            --bytes;
    }
    else {
        PyErr_SetString(PyExc_ValueError, "'bits' may not be negative");
        PyBuffer_Release(&buf);
        return NULL;
    }

    SKEIN_LOCK(self);
    if (!self->missing_bits) {  /* well aligned */
        /* hash whole bytes */
        if (!hash_bytes(self, buf.buf, bytes))
            goto update_error;

        /* hash remaining bits */
        if (bits) {
            if (!hash_bytes(self, (u08b_t *)buf.buf + bytes, 1))
                goto update_error;
            self->b[self->bCnt-1] = (self->b[self->bCnt-1]
                                     & (((1<<bits)-1) << (8-bits)))
                                     | (1<<(7-bits));
            self->missing_bits = 8-bits;
        }
    }
    else {  /* unaligned */
        if (bytes || (bits > self->missing_bits)) {
            PyErr_Format(PyExc_ValueError,
                         "<=%d bits required for byte alignment",
                         self->missing_bits);
            goto update_error;
        }
        self->b[self->bCnt-1] = (self->b[self->bCnt-1]
             & (~(1<<(self->missing_bits-1))))
             | ((((u08b_t *)buf.buf)[0]>>(8-bits))<<(self->missing_bits-bits));
        self->missing_bits -= bits;
        if (self->missing_bits)
            self->b[self->bCnt-1] |= 1<<(self->missing_bits-1);
    }
    SKEIN_UNLOCK(self);

finished:
    PyBuffer_Release(&buf);
    Py_RETURN_NONE;

update_error:
    SKEIN_UNLOCK(self);
    PyBuffer_Release(&buf);
    return NULL;
}

PyDoc_STRVAR(skein_digest__doc__,
"Return the digest value as a bytes object.");

static PyObject *
skein_digest(skeinObject *self, PyObject *args)
{
    Py_ssize_t argc = PyTuple_Size(args);
    u64b_t len = (self->digestBits-1)/8+1;
    u64b_t start = 0;
    u64b_t stop = len;
    PyObject *rv = NULL;

    if (argc != 0 && argc != 2) {
        PyErr_SetString(PyExc_TypeError,
                        "digest() takes either 0 or 2 parameters");
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "|KK:digest", &start, &stop))
        return NULL;
    if (stop > len || start > stop) {
        PyErr_SetString(PyExc_ValueError,
            "digest(start, stop) has to fulfill 0<=start<=stop<=digest_size");
        return NULL;
    }

    rv = PyBytes_FromStringAndSize(NULL, stop-start);
    if (rv == NULL)
        return NULL;
    if (start < stop) {
        SKEIN_LOCK(self);
        output_hash(self, (u08b_t *)PyBytes_AsString(rv), start, stop);
        SKEIN_UNLOCK(self);
    }
    return rv;
}

PyDoc_STRVAR(skein_hexdigest__doc__,
"Return the digest value as a string of hexadecimal digits.");

static PyObject *
skein_hexdigest(skeinObject *self, PyObject *nothing)
{
    Py_ssize_t len = (self->digestBits-1)/8+1;
    Py_ssize_t hexlen = 2*len;
    char nib = 0;
    PyObject *rv = NULL;
    u08b_t *hashVal = NULL;
    char *hex = NULL;

    if ((hashVal = PyMem_Malloc(len)) == NULL)
        return PyErr_NoMemory();
    if ((hex = PyMem_Malloc(hexlen)) == NULL) {
        PyMem_Free(hashVal);
        return PyErr_NoMemory();
    }

    SKEIN_LOCK(self);
    output_hash(self, hashVal, 0, len);
    SKEIN_UNLOCK(self);
    for (Py_ssize_t i = 0, j = 0; i < len; i++) {
        nib = (hashVal[i] >> 4) & 0x0F;
        hex[j++] = (nib<10) ? '0'+nib : 'a'-10+nib;
        nib = hashVal[i] & 0x0F;
        hex[j++] = (nib<10) ? '0'+nib : 'a'-10+nib;
    }
    rv = PyUnicode_FromStringAndSize(hex, hexlen);
    PyMem_Free(hashVal);
    PyMem_Free(hex);
    return rv;
}


PyDoc_STRVAR(skein_copy__doc__, "Return a copy of the hash object.");

static PyObject *
skein_copy(skeinObject *self, PyObject *nothing)
{
    skeinObject *new_obj = new_skein_object();
    PyObject *t = NULL;
    int res = 0;

    if (new_obj == NULL)
        return NULL;
    SKEIN_LOCK(self);
    t = skein_getstate(self);
    SKEIN_UNLOCK(self);
    if (t == NULL) {
        Py_DECREF(new_obj);
        return NULL;
    }
    res = skein_setstate(new_obj, t);
    Py_DECREF(t);
    if (res)
        return (PyObject *)new_obj;
    Py_DECREF(new_obj);
    PyErr_SetString(PyExc_RuntimeError, "internal error");
    return NULL;
}


static PyMethodDef skein_methods[] = {
    {"__reduce__", (PyCFunction)skein___reduce__, METH_VARARGS, NULL},
    {"__reduce_ex__", (PyCFunction)skein___reduce__, METH_VARARGS, NULL},
    {"digest", (PyCFunction)skein_digest, METH_VARARGS,
        skein_digest__doc__},
    {"hexdigest", (PyCFunction)skein_hexdigest, METH_NOARGS,
        skein_hexdigest__doc__},
    {"update", (PyCFunction)skein_update, METH_VARARGS|METH_KEYWORDS,
        skein_update__doc__},
    {"copy", (PyCFunction)skein_copy, METH_VARARGS,
        skein_copy__doc__},
    {NULL, NULL}
};


/* threefish object methods */

PyDoc_STRVAR(threefish_encrypt_block__doc__,
"Encrypt the given block.");

static PyObject *
threefish_encrypt_block(threefishObject *self, PyObject *args)
{
    u64b_t w[16] = {0};
    u64b_t out[16] = {0};
    u64b_t kw[SKEIN_MAX_STATE_WORDS+4];  /* local snapshot of key schedule */
    Py_ssize_t len = self->blockBytes;
    char *q = NULL;
    Py_buffer buf = {0};
    PyObject *rv = NULL;

    if (!PyArg_ParseTuple(args, "y*:encrypt", &buf))
        return NULL;
    if (buf.len != len) {
        PyErr_Format(PyExc_ValueError,
                     "block must have same length as key (%d bytes)", len);
        PyBuffer_Release(&buf);
        return NULL;
    }

    /* set up output buffer */
    rv = PyBytes_FromStringAndSize(NULL, len);
    if (rv == NULL) {
        PyBuffer_Release(&buf);
        return NULL;
    }
    if ((q = PyBytes_AsString(rv)) == NULL) {
        Py_DECREF(rv);
        PyBuffer_Release(&buf);
        return NULL;
    }

    /* Snapshot the key schedule under the lock so concurrent set_tweak calls
       cannot produce a torn read. Encryption itself runs lock-free. */
    SKEIN_LOCK(self);
    memcpy(kw, self->kw, sizeof(kw));
    SKEIN_UNLOCK(self);

    BYTES_TO_WORDS(w, buf.buf, len/8);
    self->encryptor(kw+3, kw, w, out, 0);
    WORDS_TO_BYTES((u08b_t *)q, out, len);
    PyBuffer_Release(&buf);
    return rv;
}


PyDoc_STRVAR(threefish_decrypt_block__doc__,
"Decrypt the given block.");

static PyObject *
threefish_decrypt_block(threefishObject *self, PyObject *args)
{
    u64b_t w[16] = {0};
    u64b_t out[16] = {0};
    u64b_t kw[SKEIN_MAX_STATE_WORDS+4];  /* local snapshot of key schedule */
    Py_ssize_t len = self->blockBytes;
    char *q = NULL;
    Py_buffer buf = {0};
    PyObject *rv = NULL;

    if (!PyArg_ParseTuple(args, "y*:decrypt", &buf))
        return NULL;
    if (buf.len != len) {
        PyErr_Format(PyExc_ValueError,
                     "block must have same length as key (%d bytes)", len);
        PyBuffer_Release(&buf);
        return NULL;
    }

    /* set up output buffer */
    rv = PyBytes_FromStringAndSize(NULL, len);
    if (rv == NULL) {
        PyBuffer_Release(&buf);
        return NULL;
    }
    if ((q = PyBytes_AsString(rv)) == NULL) {
        Py_DECREF(rv);
        PyBuffer_Release(&buf);
        return NULL;
    }

    /* Snapshot the key schedule under the lock so concurrent set_tweak calls
       cannot produce a torn read. Decryption itself runs lock-free. */
    SKEIN_LOCK(self);
    memcpy(kw, self->kw, sizeof(kw));
    SKEIN_UNLOCK(self);

    BYTES_TO_WORDS(w, buf.buf, len/8);
    self->decryptor(kw+3, kw, w, out);
    WORDS_TO_BYTES((u08b_t *)q, out, len);
    PyBuffer_Release(&buf);
    return rv;
}


static PyMethodDef threefish_methods[] = {
    {"encrypt_block", (PyCFunction)threefish_encrypt_block, METH_VARARGS,
        threefish_encrypt_block__doc__},
    {"decrypt_block", (PyCFunction)threefish_decrypt_block, METH_VARARGS,
        threefish_decrypt_block__doc__},
    {NULL, NULL}
};


/* types */

static void
skein_dealloc(PyObject *self)
{
    skein_state_t *level = NULL;
    skein_state_t *prev = NULL;

    /* free linked list of tree buffers */
    level = ((skeinObject *)self)->state.next_tree_level;
    while (level != NULL) {
        prev = level;
        level = level->next_tree_level;
        PyMem_Free(prev);
    }

    Py_TYPE(self)->tp_free(self);
}

static void
threefish_dealloc(PyObject *self)
{
    Py_TYPE(self)->tp_free(self);
}

static PyTypeObject skeinType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_skein.skein",                /* tp_name */
    sizeof(skeinObject),           /* tp_basicsize */
    0,                             /* tp_itemsize */
    skein_dealloc,                 /* tp_dealloc */
    0,                             /* tp_print */
    0,                             /* tp_getattr */
    0,                             /* tp_setattr */
    0,                             /* tp_compare */
    (reprfunc)skein_repr,          /* tp_repr */
    0,                             /* tp_as_number */
    0,                             /* tp_as_sequence */
    0,                             /* tp_as_mapping */
    0,                             /* tp_hash */
    0,                             /* tp_call */
    0,                             /* tp_str */
    0,                             /* tp_getattro */
    0,                             /* tp_setattro */
    0,                             /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,            /* tp_flags */
    0,                             /* tp_doc */
    0,                             /* tp_traverse */
    0,                             /* tp_clear */
    0,                             /* tp_richcompare */
    0,                             /* tp_weaklistoffset */
    0,                             /* tp_iter */
    0,                             /* tp_iternext */
    skein_methods,                 /* tp_methods */
    NULL,                          /* tp_members */
    skein_getseters                /* tp_getset */
};

static PyTypeObject threefishType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_skein.threefish",       /* tp_name */
    sizeof(threefishObject),  /* tp_basicsize */
    0,                        /* tp_itemsize */
    threefish_dealloc,        /* tp_dealloc */
    0,                        /* tp_print */
    0,                        /* tp_getattr */
    0,                        /* tp_setattr */
    0,                        /* tp_compare */
    0,                        /* tp_repr */
    0,                        /* tp_as_number */
    0,                        /* tp_as_sequence */
    0,                        /* tp_as_mapping */
    0,                        /* tp_hash */
    0,                        /* tp_call */
    0,                        /* tp_str */
    0,                        /* tp_getattro */
    0,                        /* tp_setattro */
    0,                        /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,       /* tp_flags */
    0,                        /* tp_doc */
    0,                        /* tp_traverse */
    0,                        /* tp_clear */
    0,                        /* tp_richcompare */
    0,                        /* tp_weaklistoffset */
    0,                        /* tp_iter */
    0,                        /* tp_iternext */
    threefish_methods,        /* tp_methods */
    NULL,                     /* tp_members */
    threefish_getseters       /* tp_getset */
};


/* factory functions */

/*
    The states of all tree levels are kept in a linked list starting with
    the skeinObject's "state". The last state in the list is always a copy
    of the context before the tree hashing, and each new tree level state
    will be cloned from it.

    The list is initialized with two states. The first one is special as it
    contains the leaf size instead of the node size and a function pointer to
    "tree_block_processor" instead of the relevant basic processor. This
    ensures that calling "sk->state.block_processor" leads to tree hashing.
    It also means that we can always get the basic processor from
    "next_tree_level->block_processor".
*/

static int
init_tree(skein_state_t *state,
          u08b_t tree_leaf, u08b_t tree_fan, u08b_t tree_max)
{
    skein_state_t *end = NULL;

    /* initialize the second state */
    end = PyMem_Malloc(sizeof(skein_state_t));
    if (end == NULL) {
        PyErr_NoMemory();
        return 0;
    }
    memcpy(end->X, state->X, sizeof(end->X));
    memcpy(end->T, state->T, sizeof(end->T));
    end->block_processor = state->block_processor; /* basic processor */
    end->tree_blocks = end->remaining_tree_blocks = 1<<((u64b_t)tree_fan);
    end->next_tree_level = NULL;

    /* initialize the first state (= first tree level) */
    state->block_processor = &tree_block_processor;
    state->tree_blocks = state->remaining_tree_blocks = 1<<((u64b_t)tree_leaf);
    state->remaining_tree_levels = tree_max-1;
    state->next_tree_level = end;
    state->T[1] |= ((u64b_t)1)<<SKEIN_T1_POS_LEVEL;
    return 1;
}

int
init_skein(skeinObject *new_obj, PyObject *args, PyObject *kw,
           int stateBits, const char *paramStr)
{
    Py_buffer buf = {0};
    Py_buffer key = {0};
    Py_buffer pers = {0};
    Py_buffer pk = {0};
    Py_buffer kid = {0};
    Py_buffer nonce = {0};
    PyObject *tree = NULL;
    PyObject *seq = NULL;
    PyObject *dbobj = NULL;
    u08b_t tree_leaf = 0;
    u08b_t tree_fan = 0;
    u08b_t tree_max = 0;
    u64b_t digestBits = stateBits;  /* default value */
    static char *kwlist[] = {"init", "digest_bits", "key", "pers",
                             "public_key", "key_id", "nonce", "tree", NULL};
    /* Not static: each call writes digestBits and tree params into this buffer,
       so a shared static would be a data race in free-threaded builds. */
    u08b_t cfg_block[SKEIN_MAX_STATE_WORDS*8]
        = {0x53, 0x48, 0x41, 0x33, 0x01};  /* "SHA3", version 1 */
    static const char *tree_errmsg = "'tree' must be triple of tree parameters";

    /* parse arguments */
    if (Py_SIZE(args) > 2) {
        PyErr_SetString(PyExc_TypeError,
            "all arguments except 'init' and 'digest_bits' are keyword-only");
        return 0;
    }
    buf.buf = key.buf = pers.buf = pk.buf = kid.buf = nonce.buf = tree = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kw, paramStr, kwlist,
                                     &buf, &dbobj, &key, &pers, &pk, &kid,
                                     &nonce, &tree))
            goto error;
    if (dbobj) {
        digestBits = PyLong_AsUnsignedLongLong(dbobj);
        if (PyErr_Occurred()) {
            /* Only convert expected conversion errors to ValueError;
               propagate MemoryError/KeyboardInterrupt/etc. unchanged. */
            if (!PyErr_ExceptionMatches(PyExc_OverflowError) &&
                !PyErr_ExceptionMatches(PyExc_TypeError))
                goto error;
            PyErr_Clear();
            PyErr_SetString(PyExc_ValueError,
                            "digest_bits must be between 1 and 2**64-1");
            goto error;
        }
        if (digestBits == 0) {
            PyErr_SetString(PyExc_ValueError,
                            "digest_bits must be between 1 and 2**64-1");
            goto error;
        }
    }

    /* check tree parameters */
    if (tree != NULL && tree != Py_None) {
        /* check that we have a sequence of length 3, TypeError otherwise */
        if ((seq=PySequence_Fast(tree, tree_errmsg)) == NULL)
            goto error;
        if (PySequence_Length(seq) != 3) {
            Py_CLEAR(seq);
            PyErr_SetString(PyExc_TypeError, tree_errmsg);
            goto error;
        }
        /* fill in the tree parameters */
        if (!((tree_leaf=get_tree_param(seq, 0, 1, 56))
              && (tree_fan=get_tree_param(seq, 1, 1, 56))
              && (tree_max=get_tree_param(seq, 2, 2, 255)))) {
            Py_CLEAR(seq);
            goto error;
        }
        Py_CLEAR(seq);
    }

    /* initialize skein object — all-zero chaining value before any UBI call */
    memset(new_obj->state.X, 0, sizeof(new_obj->state.X));
    new_obj->digestBits = digestBits;
    new_obj->stateBytes = stateBits / 8;
    new_obj->hashed_bytes = 0;
    new_obj->missing_bits = 0;

    /*
     * UBI chaining sequence (spec §2.1, Fig. 1):
     *
     * Each input type is processed through a separate UBI call in a fixed
     * order.  The output chaining value of one call feeds the key (chaining
     * state) for the next.  Domain separation comes from the block-type field
     * in the tweak, so even identical byte strings for different inputs produce
     * unrelated chaining values.
     *
     * Order: key → config → personalization → public-key → key-id → nonce →
     *        message → (output, done separately in output_hash)
     *
     * The config block is always present; all others are conditional.  It
     * encodes the magic "SHA3" marker, protocol version, output length, and
     * tree parameters, binding every digest to these parameters.
     */

    /* optional key (for MAC / KDF use cases) */
    if (key.buf && key.len)
        HASH_BLOCKS(new_obj, key.buf, key.len, KEY)

    /* mandatory config block: "SHA3"\x01\x00 + digest_bits (8 bytes) +
       tree params (3 bytes); processed as a single FIRST|FINAL block */
    WORDS_TO_BYTES(cfg_block+8, &digestBits, 8);
    cfg_block[16] = tree_leaf;
    cfg_block[17] = tree_fan;
    cfg_block[18] = tree_max;
    HASH_BLOCK(new_obj, cfg_block, 32, CFG)

    /* optional additional input types */
    if (pers.buf && pers.len)
        HASH_BLOCKS(new_obj, pers.buf, pers.len, PERS);
    if (pk.buf && pk.len)
        HASH_BLOCKS(new_obj, pk.buf, pk.len, PK);
    if (kid.buf && kid.len)
        HASH_BLOCKS(new_obj, kid.buf, kid.len, KID);
    if (nonce.buf && nonce.len)
        HASH_BLOCKS(new_obj, nonce.buf, nonce.len, NONCE);

    /* begin the message UBI call; caller will stream message data via update() */
    HASH_INIT(new_obj, MSG);
    if (tree_max)
        if (!init_tree(&new_obj->state, tree_leaf, tree_fan, tree_max))
            goto error;

    if (key.buf != NULL)
        PyBuffer_Release(&key);
    if (pers.buf != NULL)
        PyBuffer_Release(&pers);
    if (pk.buf != NULL)
        PyBuffer_Release(&pk);
    if (kid.buf != NULL)
        PyBuffer_Release(&kid);
    if (nonce.buf != NULL)
        PyBuffer_Release(&nonce);

    if (buf.buf != NULL) {
        if (!hash_bytes(new_obj, buf.buf, buf.len))
            goto error;
        PyBuffer_Release(&buf);
    }
    return 1;

error:
    if (buf.buf != NULL)
        PyBuffer_Release(&buf);
    if (key.buf != NULL)
        PyBuffer_Release(&key);
    if (pers.buf != NULL)
        PyBuffer_Release(&pers);
    if (pk.buf != NULL)
        PyBuffer_Release(&pk);
    if (kid.buf != NULL)
        PyBuffer_Release(&kid);
    if (nonce.buf != NULL)
        PyBuffer_Release(&nonce);
    new_obj->state.next_tree_level = NULL;  /* otherwise dealloc gets problems */
    return 0;
}

#define FACTORYDEF(N)  \
PyDoc_STRVAR(skein ## N ## _new__doc__,  \
"skein" #N "(init=b'', digest_bits=" #N ", key=b'', pers=b'', nonce=b'', " \
           "tree=None)\n\n" \
"Return a new Skein-" #N " hash object.\n\n"); \
\
static PyObject * \
skein ## N ## _new(PyObject *self, PyObject *args, PyObject *kw) \
{ \
    skeinObject *new_obj = NULL; \
\
    if ((new_obj=new_skein_object()) == NULL) \
        return NULL; \
    new_obj->state.block_processor = &Skein_ ## N ## _Process_Block; \
    if (init_skein(new_obj, args, kw, N, "|y*Oy*y*y*y*y*O:skein" #N)) \
        return (PyObject *)new_obj; \
    else { \
        Py_CLEAR(new_obj); \
        return NULL; \
    }\
}
FACTORYDEF(256)
FACTORYDEF(512)
FACTORYDEF(1024)


static PyObject *
skein__from_state(PyObject *self, PyObject *args)
{
    PyObject *t = NULL;
    skeinObject *new_obj = NULL;

    if (!PyArg_ParseTuple(args, "O!:_from_state", &PyTuple_Type, &t))
        return NULL;
    if ((new_obj=new_skein_object()) == NULL)
        return NULL;
    if (skein_setstate(new_obj, t))
        return (PyObject *)new_obj;
    Py_DECREF(new_obj);
    PyErr_SetString(PyExc_ValueError, "invalid state");
    return NULL;
}


PyDoc_STRVAR(threefish_new__doc__,
"threefish(key, tweak)\n\n"
"Return a new Threefish encryption object.");

static PyObject *
threefish_new(PyObject *self, PyObject *args)
{
    threefishObject *new_obj = NULL;
    Py_buffer key = {0};
    Py_buffer tweak = {0};
    void *encryptor = NULL;
    void *decryptor = NULL;

    if (!PyArg_ParseTuple(args, "y*y*:threefish", &key, &tweak))
        return NULL;

    switch (key.len) {
        case 32:
            encryptor = &Threefish_256_encrypt;
            decryptor = &Threefish_256_decrypt;
            break;
        case 64:
            encryptor = &Threefish_512_encrypt;
            decryptor = &Threefish_512_decrypt;
            break;
        case 128:
            encryptor = &Threefish_1024_encrypt;
            decryptor = &Threefish_1024_decrypt;
            break;
        default:
            PyErr_SetString(PyExc_ValueError,
                            "key must be 32, 64 or 128 bytes long");
            goto error;
    }
    if (tweak.len != 16) {
        PyErr_SetString(PyExc_ValueError, "tweak must be 16 bytes long");
        goto error;
    }

    /* create object */
    new_obj = PyObject_New(threefishObject, &threefishType);
    if (new_obj == NULL)
        goto error;
    new_obj->encryptor = encryptor;
    new_obj->decryptor = decryptor;
    new_obj->blockBytes = key.len;
#ifdef Py_GIL_DISABLED
    new_obj->lock = (PyMutex){0};
#endif

    /*
     * Precompute the key schedule (kw[] layout, see threefish.h).
     *
     * kw[0..1]  = tweak words T0, T1 (parsed from `tweak`)
     * kw[2]     = T2 = T0^T1  (extended tweak parity; recomputed each block
     *                           when used inside Skein, but fixed here for the
     *                           standalone Threefish object)
     * kw[3..]   = key words k0..k_{N-1}
     * kw[3+N]   = k_N = SKEIN_KS_PARITY ^ k0 ^ ... ^ k_{N-1}
     *                   (extra key word derived via the parity constraint so
     *                    the XOR of all N+1 subkeys equals SKEIN_KS_PARITY)
     */
    BYTES_TO_WORDS(new_obj->kw, tweak.buf, 2);
    BYTES_TO_WORDS(new_obj->kw+3, key.buf, key.len/8);
    new_obj->kw[2] = new_obj->kw[0] ^ new_obj->kw[1];
    new_obj->kw[3+key.len/8] = SKEIN_KS_PARITY;
    for (int i = 3; i < 3+key.len/8; i++)
        new_obj->kw[3+key.len/8] ^= new_obj->kw[i];

    PyBuffer_Release(&key);
    PyBuffer_Release(&tweak);
    return (PyObject *)new_obj;

error:
    PyBuffer_Release(&key);
    PyBuffer_Release(&tweak);
    return NULL;
}


#define METHODDEFLINE(X) \
{"skein" #X , (PyCFunction)skein ## X ## _new, METH_VARARGS|METH_KEYWORDS, \
skein ## X ## _new__doc__}

static struct PyMethodDef skein_functions[] = {
    METHODDEFLINE(256),
    METHODDEFLINE(512),
    METHODDEFLINE(1024),
    {"_from_state", (PyCFunction)skein__from_state, METH_VARARGS, NULL},
    {"threefish", (PyCFunction)threefish_new, METH_VARARGS,
     threefish_new__doc__},
    {NULL, NULL}
};


/* module init (multi-phase, PEP 451) */

static int
skein_module_exec(PyObject *m)
{
    if (PyType_Ready(&skeinType) < 0 || PyType_Ready(&threefishType) < 0)
        return -1;
    return 0;
}

static PyModuleDef_Slot skein_module_slots[] = {
    {Py_mod_exec, skein_module_exec},
    /* Support multiple interpreters: the only C-level state is the two static
       PyTypeObject structs, which are written once at type-readying time and
       thereafter read-only — safe to share across sub-interpreters. */
#if PY_VERSION_HEX >= 0x030c0000
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
#ifdef Py_GIL_DISABLED
    /* Declare that this extension is safe to use without the GIL.
       All mutable per-object state is protected by PyMutex. */
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
#endif
    {0, NULL}
};

static struct PyModuleDef skeinmodule = {
    PyModuleDef_HEAD_INIT,
    "_skein",
    NULL,
    0,              /* m_size: 0 = no module state; module is stateless */
    skein_functions,
    skein_module_slots,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit__skein(void)
{
    return PyModuleDef_Init(&skeinmodule);
}
