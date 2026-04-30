import pathlib
import pickle
import random
import re
import sysconfig
import threading
from itertools import combinations

import pytest

import _skein
import skein

KATFILE = pathlib.Path(__file__).parent / "skein_golden_kat.txt"

# Concurrent-mutation tests are meaningful only on a free-threaded build:
# SKEIN_LOCK is a real PyMutex there, while on a GIL build it compiles to a
# no-op (the GIL is sufficient for state isolation across *different*
# instances, but `hash_bytes` deliberately drops the GIL during sequential
# hashing, so concurrent updates of the *same* instance can race).
_FT_BUILD = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
_requires_ft = pytest.mark.skipif(
    not _FT_BUILD, reason="requires free-threaded build (Py_GIL_DISABLED)")


# ---------------------------------------------------------------------------
# Hasher factory used by the tree-mode subclass below.  Wrapping the
# constructor here (rather than passing tree=(1,2,3) at every call site)
# keeps the mixin tests source-identical regardless of mode.
# ---------------------------------------------------------------------------
def _skein1024_tree(*args, **kwargs):
    return skein.skein1024(*args, tree=(1, 2, 3), **kwargs)


_SKIP_TREE = pytest.mark.skip(reason="not applicable in tree mode")


# ---------------------------------------------------------------------------
# Module-level basics
# ---------------------------------------------------------------------------
def test_module_basics():
    assert skein.StreamCipher.DIGEST_BITS == 2 ** 64 - 1
    # All skein* factories share a single C type.
    assert type(skein.skein256()) is type(skein.skein512())
    assert type(skein.skein256()) is type(skein.skein1024())


# ---------------------------------------------------------------------------
# W1 / W2 / W3 thread-safety regression guards
# ---------------------------------------------------------------------------
### See TestPRNGAndCipher below for thread-safety, Random, RandomBytes,
### StreamCipher, and PRNG-stream regression tests.


# ---------------------------------------------------------------------------
# Per-hasher tests
#
# `_SkeinHasherTests` is the shared test body.  Subclasses TestSkein256 /
# 512 / 1024 / 1024Tree set the `factory` and `state_bits` class attributes;
# pytest collects each test method per concrete subclass.  The `_` prefix
# stops pytest from also collecting tests on the base.
#
# Tree-mode skips its inapplicable cases via @_SKIP_TREE overrides.
# ---------------------------------------------------------------------------
class _SkeinHasherTests:
    factory = staticmethod(lambda *a, **kw: None)   # set by subclass
    state_bits = 0                                   # set by subclass

    def test_multiple_digests(self):
        h = self.factory()
        assert h.digest() == h.digest()
        assert h.hexdigest() == h.hexdigest()

    def test_hex_digest_matches_digest(self):
        h = self.factory()
        st = "".join(format(b, "02x") for b in h.digest())
        assert h.hexdigest() == st

    def test_bit_hashing(self):
        msg = bytes(random.randrange(256) for _ in range(130))
        for bits in range(8 * 130):
            reference = self.factory(msg).digest()
            h = self.factory()
            h.update(msg, bits=bits)
            h.update(bytes([(msg[bits // 8] << (bits % 8)) & 0xff]),
                     bits=8 - bits % 8)
            h.update(msg[bits // 8 + 1:])
            assert h.digest() == reference

    def test_digest_slice(self):
        for bits in (list(range(248, 265)) + [511, 512, 513]
                     + [1023, 1024, 1025]):
            h = self.factory(bytes(random.randrange(256) for _ in range(10)),
                             digest_bits=bits)
            ref = h.digest()
            for start in range(h.digest_size):
                for stop in range(start + 1, h.digest_size + 1):
                    assert ref[start:stop] == h.digest(start, stop)

    def test_digest_slice_low_byte_clear(self):
        # When digest_bits is not a multiple of 8 the spec masks the unused
        # low bits of the final byte; digest(0, 1) must agree with
        # digest(0, 10)[:1].
        for i in range(1, 100):
            h = self.factory(digest_bits=2 ** 64 - i)
            assert h.digest(0, 10)[:1] == h.digest(0, 1)

    def test_empty_slice(self):
        assert self.factory().digest(0, 0) == b""
        h = self.factory()
        assert h.digest(h.digest_size, h.digest_size) == b""

    def test_init_argument_matches_update(self):
        a = self.factory()
        a.update(b"\xff")
        assert self.factory(b"\xff").digest() == a.digest()

    def test_repr(self):
        assert repr(self.factory()).startswith(
            f"<Skein-{self.state_bits} hash object at ")

    def test_hashed_count(self):
        h = self.factory()
        h.update(b"123")
        assert h.hashed_bits == 8 * 3
        h.update(b"12345")
        assert h.hashed_bits == 8 * 8
        h.update(b"12345", bits=5)
        assert h.hashed_bits == 8 * 8 + 5
        h.update(b"12345", bits=3)
        assert h.hashed_bits == 9 * 8

    def test_copy_independent(self):
        for e in range(6):
            length = 10 ** e
            a = self.factory(bytes(x % 256 for x in range(length)))
            b = a.copy()
            assert a.digest() == b.digest()
            assert a.hashed_bits == b.hashed_bits
            a.update(bytes(bytes(x % 256 for x in range(1, length + 2))))
            assert a.digest() != b.digest()
            b.update(bytes(bytes(x % 256 for x in range(1, length + 2))))
            assert a.digest() == b.digest()

    def test_pickle_round_trip(self):
        h = self.factory()
        h.update(bytes(x % 256 for x in range(10000)))
        copy = pickle.loads(pickle.dumps(h))
        assert h.digest() == copy.digest()

    # Combined valid-and-invalid digest_bits matrix.  None as `expected_exc`
    # means the construction must succeed and round-trip the requested value.
    @pytest.mark.parametrize("bits,expected_exc", [
        pytest.param(1,            None,       id="1"),
        pytest.param(2 ** 31 - 1,  None,       id="int32-max"),
        pytest.param(2 ** 32,      None,       id="2**32"),
        pytest.param(2 ** 63,      None,       id="2**63"),
        pytest.param(2 ** 64 - 1,  None,       id="uint64-max"),
        pytest.param(0,            ValueError, id="zero"),
        pytest.param(-1,           ValueError, id="negative"),
        pytest.param(2 ** 64,      ValueError, id="overflow"),
        pytest.param(2 ** 64 + 8,  ValueError, id="overflow+8"),
    ])
    def test_digest_sizes(self, bits, expected_exc):
        if expected_exc is None:
            assert self.factory(digest_bits=bits).digest_bits == bits
        else:
            with pytest.raises(expected_exc):
                self.factory(digest_bits=bits)

    def test_attributes(self):
        for digest_bits in range(1, 2049):
            h = self.factory(digest_bits=digest_bits)
            assert h.block_size * 8 == self.state_bits
            assert h.block_bits == self.state_bits
            assert h.digest_size == (digest_bits + 7) // 8
            assert h.digest_bits == digest_bits
            assert h.name == f"Skein-{self.state_bits}"
            assert h.hashed_bits == 0

    def test_init_arg_combinations(self):
        for n in range(8):
            for kws in combinations(
                    ["init", "digest_bits", "key", "pers",
                     "public_key", "key_id", "nonce"], n):
                kwdict = {
                    kw: b"bar" + bytes([i]) if kw != "digest_bits" else i + 1
                    for i, kw in enumerate(kws)
                }
                self.factory(**kwdict)

    @pytest.mark.parametrize("kw", ["key", "pers", "public_key",
                                     "key_id", "nonce"])
    def test_empty_optional_arg(self, kw):
        baseline = self.factory(b"foo").digest()
        assert self.factory(b"foo", **{kw: b""}).digest() == baseline

    def test_empty_combined_optional_args(self):
        baseline = self.factory(b"foo").digest()
        assert self.factory(b"foo", pers=b"", nonce=b"").digest() == baseline

    def test_keyword_only(self):
        with pytest.raises(TypeError):
            self.factory(b"foo", 512, b"bar")

    # ---- tree-parameter validation (sequential-mode only) -----------------
    def test_tree_default_matches_no_tree(self):
        assert self.factory().digest() == self.factory(tree=None).digest()

    @pytest.mark.parametrize("bad,exc", [
        # Wrong shape / wrong element type → TypeError
        pytest.param("", TypeError, id="empty-string"),
        pytest.param(1, TypeError, id="int"),
        pytest.param((1,), TypeError, id="1-tuple"),
        pytest.param((1, 2), TypeError, id="2-tuple"),
        pytest.param(("a", "b", "c"), TypeError, id="string-elems"),
        pytest.param((1.5, 1, 2), TypeError, id="float-elem"),
        # Right shape, out-of-range numeric values → ValueError
        pytest.param((0, 0, 0), ValueError, id="all-zero"),
        pytest.param((-1, 1, 2), ValueError, id="negative-leaf"),
        pytest.param((1, -100000, 2), ValueError, id="negative-fan"),
        pytest.param((1, 1, 1), ValueError, id="max-too-small"),
        pytest.param((10 ** 20, 1, 2), ValueError, id="huge-leaf"),
        pytest.param((1, -10 ** 20, 2), ValueError, id="huge-negative-fan"),
        pytest.param((256, 1, 2), ValueError, id="leaf-overflow-byte"),
    ])
    def test_tree_rejects_invalid(self, bad, exc):
        with pytest.raises(exc):
            self.factory(tree=bad)

    @pytest.mark.parametrize("good", [(1, 1, 2), (10, 20, 255)])
    def test_tree_accepts_valid(self, good):
        self.factory(tree=good)

    # ---- Random / StreamCipher hooked to this hasher ----------------------
    def test_prng_init_variants(self):
        skein.Random(hasher=self.factory)
        skein.Random(seed=42, hasher=self.factory)
        skein.Random("str", hasher=self.factory)

    def test_prng_seed_bytes_like_parity(self):
        # C-10: bytes / bytearray / memoryview seeds must produce the same
        # Skein-derived stream.
        a = skein.Random(b"hello", hasher=self.factory)
        b = skein.Random(bytearray(b"hello"), hasher=self.factory)
        c = skein.Random(memoryview(b"hello"), hasher=self.factory)
        ref = [a.random() for _ in range(5)]
        assert [b.random() for _ in range(5)] == ref
        assert [c.random() for _ in range(5)] == ref

    def test_prng_state_inspection(self):
        r = skein.Random(b"x", hasher=self.factory)
        state = r._state
        assert state == self.factory(bytes(self.state_bits // 8) + b"x").digest()
        # After random() the state advances by one threefish block.
        r.random()
        t = skein.threefish(state, bytes(15) + bytes([63]))
        assert r._state == t.encrypt_block(bytes(self.state_bits // 8))

    def test_prng_get_set_state(self):
        r = skein.Random(b"123", hasher=self.factory)
        r.random()
        r.gauss(0, 1)
        state = r.getstate()
        a = r.random()
        b = r.gauss(0, 1)

        r = skein.Random(b"123", hasher=self.factory)
        r.setstate(state)
        assert r.random() == a
        assert r.gauss(0, 1) == b

    def test_streamcipher_round_trip(self):
        c = skein.StreamCipher(key=b"secret", hasher=self.factory)
        x = c.encrypt(b"foobar")
        c = skein.StreamCipher(key=b"secret", hasher=self.factory)
        assert c.decrypt(x) == b"foobar"

    # ---- Free-threaded safety -------------------------------------------
    # The contract under test: a concurrent mix of N update() calls on a
    # shared hasher behaves as N sequential update() calls, and hashers on
    # independent threads cannot contaminate each other.  These are
    # FT-only because hash_bytes drops the GIL during sequential hashing —
    # the per-object PyMutex (active only on a free-threaded build) is
    # what closes the race on shared-instance writes.

    @_requires_ft
    def test_concurrent_update_shared_instance(self):
        N_THREADS, N_CALLS = 8, 100
        PAYLOAD = b"shared-payload-bytes" * 4

        h = self.factory()
        barrier = threading.Barrier(N_THREADS)

        def worker():
            barrier.wait()
            for _ in range(N_CALLS):
                h.update(PAYLOAD)

        threads = [threading.Thread(target=worker) for _ in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Reference: N_THREADS * N_CALLS sequential updates of the same
        # bytes.  Equal-data updates are order-insensitive in the sense that
        # the *concatenation* is identical regardless of interleave; under
        # proper locking the C state machine processes them sequentially.
        h_ref = self.factory()
        for _ in range(N_THREADS * N_CALLS):
            h_ref.update(PAYLOAD)
        assert h.digest() == h_ref.digest()

    def test_concurrent_independent_instances(self):
        N_THREADS, REPEATS = 8, 50
        payloads = [bytes([i]) * 100 for i in range(N_THREADS)]
        expected = [self.factory(p).digest() for p in payloads]

        results = [None] * N_THREADS
        barrier = threading.Barrier(N_THREADS)

        def worker(i):
            barrier.wait()
            for _ in range(REPEATS):
                # Construct → update → digest entirely on this thread,
                # using its own data; no other thread should see it.
                results[i] = self.factory(payloads[i]).digest()

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results == expected

    @_requires_ft
    @pytest.mark.parametrize("reader", [
        pytest.param(lambda h: h.digest(),                              id="digest"),
        pytest.param(lambda h: h.copy().digest(),                       id="copy"),
        pytest.param(lambda h: pickle.loads(pickle.dumps(h)).digest(),  id="pickle"),
    ])
    def test_concurrent_reader_sees_consistent_snapshot(self, reader):
        # While 4 updater threads append the same payload to a shared
        # hasher, 4 reader threads observe via digest()/copy()/pickle.
        # Every observation must equal the digest at *some* sequential
        # update count — never a torn intermediate state.
        N_UPD, N_RD, N_OPS = 4, 4, 50
        PAYLOAD = b"x" * 32

        # Pre-compute every "valid intermediate digest" — the digest
        # observable after exactly k sequential updates have been applied.
        h_ref = self.factory()
        snapshots = [h_ref.digest()]
        for _ in range(N_UPD * N_OPS):
            h_ref.update(PAYLOAD)
            snapshots.append(h_ref.digest())
        valid = set(snapshots)

        h = self.factory()
        observed, lock = [], threading.Lock()
        barrier = threading.Barrier(N_UPD + N_RD)

        def updater():
            barrier.wait()
            for _ in range(N_OPS):
                h.update(PAYLOAD)

        def reader_worker():
            barrier.wait()
            local = [reader(h) for _ in range(N_OPS)]
            with lock:
                observed.extend(local)

        threads = ([threading.Thread(target=updater) for _ in range(N_UPD)]
                   + [threading.Thread(target=reader_worker) for _ in range(N_RD)])
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        bad = [d for d in observed if d not in valid]
        assert not bad, f"{len(bad)} of {len(observed)} torn observations seen"
        # After all updaters finish, the final digest must equal the
        # all-updates-applied snapshot (the last entry in `snapshots`).
        assert h.digest() == snapshots[-1]


class TestSkein256(_SkeinHasherTests):
    factory = staticmethod(skein.skein256)
    state_bits = 256


class TestSkein512(_SkeinHasherTests):
    factory = staticmethod(skein.skein512)
    state_bits = 512


class TestSkein1024(_SkeinHasherTests):
    factory = staticmethod(skein.skein1024)
    state_bits = 1024


class TestSkein1024Tree(_SkeinHasherTests):
    """Skein-1024 with tree parameters (1, 2, 3) baked into every call.
    Tests that don't apply to tree mode (copy and tree-parameter validation
    itself) are skipped."""
    factory = staticmethod(_skein1024_tree)
    state_bits = 1024

    @_SKIP_TREE
    def test_copy_independent(self):
        pass

    @_SKIP_TREE
    def test_tree_default_matches_no_tree(self):
        pass

    @_SKIP_TREE
    def test_tree_rejects_invalid(self):
        pass

    @_SKIP_TREE
    def test_tree_accepts_valid(self):
        pass


# ---------------------------------------------------------------------------
# Random / StreamCipher tests not parametrized by hasher (default skein512)
# ---------------------------------------------------------------------------
class TestPRNGAndCipher:
    """Cross-cutting tests for StreamCipher, Random, RandomBytes that don't
    depend on which Skein hasher is underneath (default skein512).  Includes
    the W1/W2/W3 thread-safety regression guards."""

    # --- W1/W2/W3: each class must serialise concurrent state mutation;
    # without a lock free-threaded builds reuse keystream bytes or produce
    # duplicate "random" output (two-time-pad break for the cipher).
    @pytest.mark.parametrize("ctor", [
        pytest.param(lambda: skein.StreamCipher(b"key"),  id="StreamCipher"),
        pytest.param(lambda: skein.Random(b"seed"),       id="Random"),
        pytest.param(lambda: skein.RandomBytes(b"seed"),  id="RandomBytes"),
    ])
    def test_lock_attribute_present(self, ctor):
        assert hasattr(ctor(), "_lock")

    @pytest.mark.parametrize("ctor,read", [
        # W1: every keystream slice must be unique under concurrent use.
        pytest.param(lambda: skein.StreamCipher(b"shared-key"),
                     lambda c: c.keystream(64),     id="StreamCipher"),
        # W2: Random.read() advances internal counter; concurrent reads
        # must not return overlapping byte ranges.
        pytest.param(lambda: skein.Random(b"shared-seed"),
                     lambda c: c.read(64),          id="Random"),
        # W3: RandomBytes likewise must atomically advance state.
        pytest.param(lambda: skein.RandomBytes(b"shared-seed"),
                     lambda c: c.read(64),          id="RandomBytes"),
    ])
    def test_streaming_primitive_concurrent_unique(self, ctor, read):
        obj = ctor()
        chunks = []
        chunks_lock = threading.Lock()
        barrier = threading.Barrier(4)

        def worker():
            barrier.wait()
            local = [read(obj) for _ in range(50)]
            with chunks_lock:
                chunks.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(chunks) == len(set(chunks)), \
            "stream chunks must not repeat under concurrent use"

    # --- Random PRNG stream
    def test_random_stream_split_and_whole(self):
        for i in range(0, 5000, 13):
            r = skein.Random(b"abc")
            assert r.read(i) + r.read(5000 - i) == skein.Random(b"abc").read(5000)

    def test_getrandbits_in_range(self):
        r = skein.Random()
        for k in range(16):
            for _ in range(1000):
                x = r.getrandbits(k)
                assert 0 <= x < (1 << k)

    def test_random_read_negative_n_rejected(self):
        with pytest.raises(ValueError, match=r"number of random bytes needs to be >= 0"):
            skein.Random(b"x").read(-1)

    # --- RandomBytes
    @pytest.mark.parametrize("n", [0, 1, 64, 1000])
    def test_randombytes_read_length(self, n):
        assert len(skein.RandomBytes(b"seed").read(n)) == n

    def test_randombytes_read_advances_state(self):
        rb = skein.RandomBytes(b"seed")
        assert rb.read(64) != rb.read(64), \
            "consecutive reads must produce different output"

    def test_randombytes_seed_reproducibility(self):
        a = skein.RandomBytes(b"same-seed")
        b = skein.RandomBytes(b"same-seed")
        assert a.read(256) == b.read(256)

    def test_randombytes_reseed_changes_stream(self):
        rb = skein.RandomBytes(b"first")
        before = rb.read(64)
        rb.seed(b"second")
        assert rb.read(64) != before

    # --- StreamCipher type checking
    def test_streamcipher_decrypt_rejects_str(self):
        x = skein.StreamCipher(b"secret").encrypt(b"hello world")
        c = skein.StreamCipher(b"secret")
        with pytest.raises(TypeError):
            c.decrypt("string")
        # State must roll back so the next decrypt produces correct plaintext.
        assert c.decrypt(x) == b"hello world"


# ---------------------------------------------------------------------------
# KAT (known-answer test) corpus
# ---------------------------------------------------------------------------
_KAT_HEADER_RE = re.compile(
    r":Skein-(\d+):\s+(\d+)-bit hash, "
    r"msgLen =\s+(\d+) bits(.+)")
_KAT_TREE_RE = re.compile(r"Tree: leaf=(..), node=(..), maxLevels=(..)")
_KAT_HASHERS = {256: skein.skein256, 512: skein.skein512, 1024: skein.skein1024}


def _kat_hex_to_bytes(txt):
    if "(none)" in txt:
        return b""
    lines = [line for line in txt.split("\n") if line.startswith("   ")]
    return bytes(int(x, 16) for x in "".join(lines).split())


def _load_kat_cases():
    """Yield one parametrize.param per KAT entry so each is its own test."""
    text = KATFILE.read_text()
    for block in text.split("---------\n"):
        if not block.strip():
            continue
        m = _KAT_HEADER_RE.search(block)
        if m is None:
            continue
        state_bits, digest_bits, msg_bits = map(int, m.groups()[:-1])
        rest = m.groups()[-1]
        if "Tree" in rest:
            tree_params = tuple(int(x, 16)
                                 for x in _KAT_TREE_RE.search(rest).groups())
        else:
            tree_params = None
        body = block.split("Message data:\n", 1)[1]
        if "MAC key =" in body:
            msgtxt, body = body.split("MAC key =", 1)
            _, body = body.split("\n", 1)
            mactxt, hashtxt = body.split("Result:\n")
        else:
            msgtxt, hashtxt = body.split("Result:\n")
            mactxt = ""
        yield pytest.param(
            state_bits, digest_bits, msg_bits, tree_params,
            mactxt, msgtxt, hashtxt,
            id=f"skein{state_bits}-d{digest_bits}-m{msg_bits}"
                + (f"-tree{tree_params}" if tree_params else ""),
        )


@pytest.mark.parametrize(
    "state_bits,digest_bits,msg_bits,tree_params,mactxt,msgtxt,hashtxt",
    list(_load_kat_cases()),
)
def test_kat_corpus(state_bits, digest_bits, msg_bits, tree_params,
                    mactxt, msgtxt, hashtxt):
    h = _KAT_HASHERS[state_bits](
        digest_bits=digest_bits,
        key=_kat_hex_to_bytes(mactxt),
        tree=tree_params,
    )
    h.update(_kat_hex_to_bytes(msgtxt), bits=msg_bits)
    assert h.digest() == _kat_hex_to_bytes(hashtxt)


# ---------------------------------------------------------------------------
# Per-Threefish tests
#
# `_ThreefishTests` is the shared body.  Subclasses set `KEYLEN`; the
# autouse fixture builds a fresh threefish object on `self.t` for each
# test method.
# ---------------------------------------------------------------------------
class _ThreefishTests:
    KEYLEN = 0  # set by subclass

    @pytest.fixture(autouse=True)
    def _build_threefish(self):
        self.t = skein.threefish(bytes(range(self.KEYLEN)), bytes(range(16)))
        # Distractor object — keeps the buffer-pool state non-trivial so
        # any buffer-handling slip would surface as a wrong-output bug.
        skein.threefish(bytes(range(self.KEYLEN)), bytes(range(11, 27)))

    def test_attributes(self):
        assert self.t.block_size == self.KEYLEN
        assert self.t.block_bits == self.KEYLEN * 8
        assert self.t.tweak == bytes(range(16))

    def test_tweak_setter_basic(self):
        with pytest.raises(TypeError):
            self.t.tweak = 0
        with pytest.raises(ValueError):
            self.t.tweak = bytes(17)
        self.t.tweak = bytes(range(1, 17))
        assert self.t.tweak == bytes(range(1, 17))

    def test_tweak_setter_accepts_bytes_like(self):
        # C-3: setter must accept any bytes-like (bytearray, memoryview)
        # to match the constructor's y* buffer-protocol parsing.
        self.t.tweak = bytearray(b"\x02" * 16)
        assert self.t.tweak == b"\x02" * 16
        self.t.tweak = memoryview(b"\x03" * 16)
        assert self.t.tweak == b"\x03" * 16
        with pytest.raises(ValueError):
            self.t.tweak = memoryview(b"\x04" * 8)

    def test_del_tweak_raises_attribute_error(self):
        # F9 regression: `del t.tweak` invoked the setter with NULL value;
        # without the new NULL guard the first PyByteArray_Check would deref
        # value->ob_type and SEGV.
        with pytest.raises(AttributeError):
            del self.t.tweak

    @pytest.mark.parametrize("method", ["encrypt_block", "decrypt_block"])
    @pytest.mark.parametrize("size_kind", [
        pytest.param("tiny",  id="size-1"),
        pytest.param("under", id="keylen-1"),
        pytest.param("over",  id="keylen+1"),
    ])
    def test_block_method_rejects_wrong_size(self, method, size_kind):
        size = {"tiny": 1,
                "under": self.KEYLEN - 1,
                "over":  self.KEYLEN + 1}[size_kind]
        with pytest.raises(ValueError):
            getattr(self.t, method)(bytes(size))

    @pytest.mark.parametrize("method", ["encrypt_block", "decrypt_block"])
    def test_block_method_rejects_non_bytes(self, method):
        # Hits the PyArg_ParseTuple `y*` failure path before the length check.
        with pytest.raises(TypeError):
            getattr(self.t, method)("string")

    def test_round_trip(self):
        for _ in range(100):
            key = bytes(random.randint(0, 255) for _ in range(self.KEYLEN))
            tweak = bytes(random.randint(0, 255) for _ in range(16))
            plain = bytes(random.randint(0, 255) for _ in range(self.KEYLEN))
            t = skein.threefish(key, tweak)
            assert t.decrypt_block(t.encrypt_block(plain)) == plain

    # ---- Free-threaded safety -------------------------------------------
    # Same intent as the corresponding _SkeinHasherTests cases: pass
    # trivially under the GIL, exercise the per-object PyMutex (which
    # protects kw[] against concurrent set_tweak vs encrypt/decrypt) on a
    # free-threaded build.

    def test_concurrent_encrypt_shared_instance(self):
        # Read-only path: many threads encrypt the same plaintext through
        # one shared threefish object, no mutation involved.  All results
        # must equal the single-threaded baseline.
        plain = bytes(self.KEYLEN)
        expected = self.t.encrypt_block(plain)

        N_THREADS, N_CALLS = 8, 100
        results = []
        results_lock = threading.Lock()
        barrier = threading.Barrier(N_THREADS)

        def worker():
            barrier.wait()
            local = [self.t.encrypt_block(plain) for _ in range(N_CALLS)]
            with results_lock:
                results.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(r == expected for r in results)

    def test_concurrent_set_tweak_then_encrypt_same_value(self):
        # Mutation path: each iteration writes the same tweak then encrypts.
        # Without the per-object PyMutex, kw[] could tear between a
        # set_tweak from one thread and an encrypt from another, producing
        # garbage output.  With the lock the kw[] read inside encrypt_block
        # always sees a consistent snapshot.
        tweak = bytes(range(16))
        plain = bytes(self.KEYLEN)
        self.t.tweak = tweak
        expected = self.t.encrypt_block(plain)

        N_THREADS, N_CALLS = 8, 50
        results = []
        results_lock = threading.Lock()
        barrier = threading.Barrier(N_THREADS)

        def worker():
            barrier.wait()
            local = []
            for _ in range(N_CALLS):
                self.t.tweak = tweak
                local.append(self.t.encrypt_block(plain))
            with results_lock:
                results.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(r == expected for r in results)

    def test_concurrent_independent_instances(self):
        # Each thread builds its own threefish from a thread-unique key
        # and encrypts a thread-unique plaintext.  No cross-thread state
        # exists, so results must match the single-threaded baseline.
        N_THREADS, REPEATS = 8, 50
        keys = [bytes([i + 1] * self.KEYLEN) for i in range(N_THREADS)]
        plains = [bytes([0xff - i] * self.KEYLEN) for i in range(N_THREADS)]
        expected = [skein.threefish(k, bytes(16)).encrypt_block(p)
                    for k, p in zip(keys, plains)]

        results = [None] * N_THREADS
        barrier = threading.Barrier(N_THREADS)

        def worker(i):
            t = skein.threefish(keys[i], bytes(16))
            barrier.wait()
            for _ in range(REPEATS):
                results[i] = t.encrypt_block(plains[i])

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results == expected


class TestThreefish32(_ThreefishTests):
    KEYLEN = 32


class TestThreefish64(_ThreefishTests):
    KEYLEN = 64


class TestThreefish128(_ThreefishTests):
    KEYLEN = 128


# ---------------------------------------------------------------------------
# Error paths in skein.update / init_skein
# ---------------------------------------------------------------------------
class TestErrorPaths:
    """Reachable error paths for skein.update / skein.digest / skein.hexdigest
    / skein.threefish constructor / init_skein.  Each test exercises a
    specific defensive branch."""

    # --- skein.update validation ------------------------------------------
    def test_update_bits_larger_than_message(self):
        h = skein.skein512()
        with pytest.raises(ValueError, match=r"'bits' larger than 8\*len\(message\)"):
            h.update(b"xx", bits=100)
        # State unchanged after failed update.
        assert h.hashed_bits == 0

    @pytest.mark.parametrize("neg", [-2, -1000])
    def test_update_negative_bits(self, neg):
        # bits=-1 is the default sentinel ("whole message"); strictly less
        # than -1 is the error path.
        h = skein.skein512()
        with pytest.raises(ValueError, match=r"'bits' may not be negative"):
            h.update(b"xx", bits=neg)
        assert h.hashed_bits == 0

    @pytest.mark.parametrize("data,bits", [
        # Whole bytes after an unaligned update is rejected.
        pytest.param(b"\x00\x00", -1, id="whole-bytes"),
        # More bits than `missing_bits` (5 missing here) is rejected.
        pytest.param(b"\x00", 6, id="too-many-bits"),
    ])
    def test_update_unaligned_followup_rejected(self, data, bits):
        h = skein.skein512()
        h.update(b"\x00", bits=3)            # leaves 5 missing bits
        kwargs = {} if bits < 0 else {"bits": bits}
        with pytest.raises(ValueError, match=r"bits required for byte alignment"):
            h.update(data, **kwargs)

    def test_update_unaligned_partial_followup(self):
        # A second sub-byte update where bits < missing_bits leaves
        # missing_bits still > 0 and exercises the "set marker bit"
        # branch in skein_update (line 1129 in _skeinmodule.c).
        h = skein.skein512()
        h.update(b"\x00", bits=3)            # missing_bits = 5 after this
        h.update(b"\x80", bits=3)            # consume 3 more → missing_bits=2
        # Reach a digest to flush the partial byte; just must not raise.
        assert len(h.digest()) == h.digest_size

    def test_update_error_paths_no_leak(self):
        # Heavy regression check for the PyBuffer_Release fixes.  RSS is a
        # coarse but effective signal over this many iterations.
        import gc, resource
        rss = lambda: resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        h = skein.skein512()
        for _ in range(1000):                 # warm up
            try:
                h.update(b"xx", bits=100)
            except ValueError:
                pass
        gc.collect()
        r0 = rss()
        for _ in range(50_000):
            try:
                h.update(b"xx", bits=100)
            except ValueError:
                pass
            try:
                h.update(b"xx", bits=-1)
            except ValueError:
                pass
        gc.collect()
        r1 = rss()
        # 1 MB drift allowance; a real leak would be many MB.
        assert abs(r1 - r0) / 1024 < 1024, \
            f"RSS grew {(r1 - r0) / 1024:.0f} KB across 100k error trips"

    def test_evil_tree_index_does_not_crash(self):
        # F12 regression: PySequence_Fast(tree, ...) returns the user's list
        # unchanged for a list input.  A custom __index__ on tree entries
        # could mutate the list mid-iteration, freeing items the subsequent
        # get_tree_param calls dereference (use-after-free).  init_skein
        # now snapshots to an immutable tuple before calling get_tree_param.
        class Evil:
            def __init__(self, list_ref):
                self.list_ref = list_ref
                self.fired = False

            def __index__(self):
                if not self.fired:
                    self.fired = True
                    self.list_ref.clear()
                return 1

        my_list = [None, None, None]
        my_list[0] = Evil(my_list)
        my_list[1] = Evil(my_list)
        my_list[2] = Evil(my_list)
        # Behaviour after self-mutation is undefined-but-safe: any of
        # success / ValueError / TypeError is acceptable, only a crash fails.
        try:
            skein.skein512(b"x", tree=my_list)
        except (TypeError, ValueError):
            pass

    def test_init_error_path_tree_no_leak(self):
        # F5 regression: init_skein's error path used to overwrite
        # next_tree_level with NULL, leaking the chaining-state linked list
        # if init_tree had already populated it.
        import gc, resource
        rss = lambda: resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        for _ in range(50):                   # warm up
            h = skein.skein512(b"x" * 1000, tree=(2, 2, 10))
            h.update(b"y" * 5000)
            del h
        gc.collect()
        r0 = rss()
        for _ in range(2000):
            h = skein.skein512(b"x" * 1000, tree=(2, 2, 10))
            h.update(b"y" * 5000)
            del h
        gc.collect()
        r1 = rss()
        assert abs(r1 - r0) / 1024 < 1024, \
            f"RSS grew {(r1 - r0) / 1024:.0f} KB across 2000 tree dealloc cycles"

    # --- digest_bits validation (init_skein PyErr_Clear guard) ------------
    @pytest.mark.parametrize("bad", [
        pytest.param("not-an-int",  id="str"),
        pytest.param(b"bytes",      id="bytes"),
        pytest.param([1, 2, 3],     id="list"),
        pytest.param({},            id="dict"),
        pytest.param(1.5,           id="float"),
        pytest.param(object(),      id="object"),
        pytest.param(2 ** 80,       id="overflow"),
    ])
    def test_digest_bits_invalid_value_or_type(self, bad):
        with pytest.raises(ValueError, match=r"digest_bits must be between 1 and 2\*\*64-1"):
            skein.skein512(digest_bits=bad)

    # --- digest()/hexdigest() validation + F1/F8/F10 caps -----------------
    @pytest.mark.parametrize("args", [(5,), (1, 2, 3)],
                              ids=["1-arg", "3-args"])
    def test_digest_arity_invalid(self, args):
        with pytest.raises(TypeError, match=r"digest\(\) takes either 0 or 2"):
            skein.skein512().digest(*args)

    def test_digest_start_after_stop(self):
        with pytest.raises(ValueError, match=r"0<=start<=stop<=digest_size"):
            skein.skein512().digest(5, 3)

    @pytest.mark.parametrize("stop", [65, 2 ** 40])
    def test_digest_stop_past_size(self, stop):
        with pytest.raises(ValueError, match=r"0<=start<=stop<=digest_size"):
            skein.skein512().digest(0, stop)

    @pytest.mark.parametrize("method", ["digest", "hexdigest"])
    def test_huge_digest_bits_capped(self, method):
        # F8 / F10 regression: digest()/hexdigest() must reject requests
        # whose byte allocation would exceed PYSKEIN_MAX_DIGEST_BYTES.
        h = skein.skein512(b"x", digest_bits=2 ** 40)
        with pytest.raises(ValueError, match="digest range too large"):
            getattr(h, method)()

    def test_digest_slice_within_cap_works(self):
        h = skein.skein512(b"x", digest_bits=2 ** 40)
        assert len(h.digest(0, 64)) == 64

    @pytest.mark.parametrize("factory,state_bytes,wrap", [
        pytest.param(skein.skein512, 64, 2 ** 38, id="skein512-256GB"),
        pytest.param(skein.skein256, 32, 2 ** 37, id="skein256-128GB"),
    ])
    def test_keystream_does_not_cycle(self, factory, state_bytes, wrap):
        # F1 regression: output_hash's per-block counter must use the full
        # 8-byte width.  With the historic 4-byte truncation the keystream
        # repeated every 2**32 blocks (= 256 GB on skein-512, 128 GB on -256).
        h = factory(b"key-material", digest_bits=2 ** 64 - 1)
        assert h.digest(0, state_bytes) != h.digest(wrap, wrap + state_bytes)

    # --- skein.threefish() constructor validation -------------------------
    @pytest.mark.parametrize("n", [0, 1, 31, 33, 48, 63, 65, 127, 129, 256])
    def test_threefish_bad_key_length(self, n):
        with pytest.raises(ValueError, match=r"key must be 32, 64 or 128 bytes long"):
            skein.threefish(bytes(n), bytes(16))

    @pytest.mark.parametrize("n", [0, 1, 8, 15, 17, 32])
    def test_threefish_bad_tweak_length(self, n):
        with pytest.raises(ValueError, match=r"tweak must be 16 bytes long"):
            skein.threefish(bytes(32), bytes(n))

    @pytest.mark.parametrize("key,tweak", [
        pytest.param("string-key", bytes(16),       id="str-key"),
        pytest.param(bytes(32),    "string-tweak",  id="str-tweak"),
    ])
    def test_threefish_non_bytes_input(self, key, tweak):
        with pytest.raises(TypeError):
            skein.threefish(key, tweak)


# ---------------------------------------------------------------------------
# _from_state validation
# ---------------------------------------------------------------------------
def _state(init=b"seed-message", **kw):
    """Build a valid pickled state tuple from a fresh skein512 hasher."""
    return skein.skein512(init, **kw).__reduce__()[1][0]


class TestFromStateValidation:
    """_skein._from_state branches in skein_setstate.  These are reachable
    via pickle, so corrupted pickles must fail with a precise exception
    rather than producing a broken skein object."""

    @pytest.mark.parametrize("bad", [
        pytest.param(1,                                id="int"),
        pytest.param("string",                          id="str"),
        # A list of the right *shape* still fails because PyArg_ParseTuple
        # uses O! against PyTuple_Type — this exercises that branch.
        pytest.param([2, 512, 64, 0, 0, b"", b"", b""], id="list"),
    ])
    def test_non_tuple_raises_typeerror(self, bad):
        with pytest.raises(TypeError):
            _skein._from_state(bad)

    @pytest.mark.parametrize("length", list(range(8)))
    def test_short_tuple(self, length):
        with pytest.raises(ValueError):
            _skein._from_state(tuple(range(length)))

    @pytest.mark.parametrize("version", [1, 3])
    def test_wrong_protocol_version(self, version):
        s = list(_state())
        s[0] = version
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s))

    @pytest.mark.parametrize("bad", [0, 7])
    def test_bad_digest_bits(self, bad):
        s = list(_state())
        s[1] = bad
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s))

    @pytest.mark.parametrize("bad", [0, 16, 96, 256])
    def test_bad_state_bytes(self, bad):
        s = list(_state())
        s[2] = bad
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s))

    def test_missing_bits_out_of_range(self):
        s = list(_state())
        s[4] = 8
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s))

    def test_missing_bits_without_buffered_byte(self):
        s = list(_state(b""))
        s[4] = 3
        s[5] = b""
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s))

    @pytest.mark.parametrize("offset,bad", [
        # s[5] = b-buffer (must be bytes ≤ stateBytes)
        pytest.param(5, "not bytes",       id="b-buffer-wrong-type"),
        pytest.param(5, b"\x00" * 1000,    id="b-buffer-too-large"),
        # s[6] = X chaining state (must be exactly stateBytes)
        pytest.param(6, b"\x00" * 5,       id="X-wrong-size"),
        # s[7] = T tweak (must be exactly 16)
        pytest.param(7, b"\x00" * 8,       id="T-wrong-size"),
    ])
    def test_intro_buffer_validation(self, offset, bad):
        s = list(_state())
        s[offset] = bad
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s))

    def test_tree_intro_incomplete(self):
        s = list(_state(tree=(2, 2, 10)))
        assert len(s) >= 15
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s[:12]))

    @pytest.mark.parametrize("extra", [1, 2])
    def test_tree_partial_final_level(self, extra):
        s = list(_state(tree=(2, 2, 10)))
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s + [b"\x00"] * extra))

    def test_tree_pickle_roundtrip(self):
        # F3 regression: skein_setstate's PyTuple_GetSlice path is reached
        # only when restoring a tree-mode hash via pickle.
        h = skein.skein512(b"data", tree=(2, 2, 10))
        h.update(b"more")
        copy = pickle.loads(pickle.dumps(h))
        assert h.digest() == copy.digest()

    def test_typeerror_from_get_tree_param_is_preserved(self):
        # C-2 regression: _from_state used to overwrite skein_setstate's
        # precise TypeError with a generic ValueError("invalid state").
        s = list(_state(tree=(2, 2, 10)))
        s[8] = 1.5      # PyFloat → get_tree_param sets TypeError
        with pytest.raises(TypeError, match="tree parameters have to be integers"):
            _skein._from_state(tuple(s))

    def test_value_error_from_get_tree_param_is_preserved(self):
        # Same C-2 fix on the ValueError side.
        s = list(_state(tree=(2, 2, 10)))
        s[8] = 0
        with pytest.raises(ValueError, match="tree parameters have to be between"):
            _skein._from_state(tuple(s))

    # --- Tree-mode level validation (s[11] + s[12..14] level-0 triple) ----
    # State layout for tree=(2, 2, 10):
    #   s[8..10]  = leaf, fan, max
    #   s[11]     = remaining-tree-blocks (8 bytes little-endian, must be ≤ 1<<leaf)
    #   s[12..14] = level-0 X | T | remaining (sizes 64 | 16 | 8)
    @pytest.mark.parametrize("offset,bad", [
        # s[11] (remaining-tree-blocks)
        pytest.param(11, "not bytes",   id="remaining-wrong-type"),
        pytest.param(11, b"\x00" * 7,   id="remaining-too-short"),
        pytest.param(11, b"\x00" * 9,   id="remaining-too-long"),
        # s[12] level-0 X
        pytest.param(12, "not bytes",   id="level0-X-wrong-type"),
        pytest.param(12, b"\x00" * 5,   id="level0-X-wrong-size"),
        # s[13] level-0 T
        pytest.param(13, b"\x00" * 8,   id="level0-T-wrong-size"),
        # s[14] level-0 remaining
        pytest.param(14, b"\x00" * 7,   id="level0-remaining-wrong-size"),
    ])
    def test_tree_level_buffer_validation(self, offset, bad):
        s = list(_state(tree=(2, 2, 10)))
        s[offset] = bad
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s))

    @pytest.mark.parametrize("offset", [
        pytest.param(11, id="remaining-tree-blocks-overflow"),
        pytest.param(14, id="level0-remaining-overflow"),
    ])
    def test_tree_remaining_overflow(self, offset):
        # Both per-level and intro-level remaining are bounded by tree_blocks
        # (which is 1<<tree_leaf at intro and 1<<tree_fan per level — both
        # equal 4 here since leaf=fan=2).  Encode 5 (>4) in 8 bytes LE.
        s = list(_state(tree=(2, 2, 10)))
        s[offset] = (5).to_bytes(8, "little")
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s))

    def test_tree_state_extra_level_past_max(self):
        # tree_max constrains how many tree levels can be encoded.  A
        # pickled state that carries one level too many must be rejected
        # (the `remaining_levels == 0` guard inside skein_setstate).
        h = skein.skein512(b"x" * 100, tree=(2, 2, 3))   # max=3
        h.update(b"y" * 5000)                             # accumulate levels
        s = list(h.__reduce__()[1][0])
        # Append one extra (X, T, remaining) triple — implies one more
        # level than tree_max permits.
        s = s + [b"\x00" * 64, b"\x00" * 16, (1).to_bytes(8, "little")]
        with pytest.raises(ValueError):
            _skein._from_state(tuple(s))
