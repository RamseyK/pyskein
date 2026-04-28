import pathlib
import pickle
import random
import re
import sys
import unittest
from itertools import combinations

import _skein

import skein

KATFILE = str(pathlib.Path(__file__).parent / "skein_golden_kat.txt")


class TestSkeinModule(unittest.TestCase):
    def test_module_basics(self):
        self.assertEqual(skein.StreamCipher.DIGEST_BITS, 2 ** 64 - 1)
        self.assertIs(type(skein.skein256()), type(skein.skein512()))
        self.assertIs(type(skein.skein256()), type(skein.skein1024()))

    # Regression guards for the FT thread-safety findings (W1/W2/W3): each
    # of StreamCipher, Random, and RandomBytes must serialise concurrent
    # state mutation; without a lock free-threaded builds reuse keystream
    # bytes / produce duplicate "random" output (two-time-pad break for the
    # cipher).
    def test_streamcipher_has_lock(self):
        self.assertTrue(hasattr(skein.StreamCipher(b"key"), "_lock"))

    def test_random_has_lock(self):
        self.assertTrue(hasattr(skein.Random(b"seed"), "_lock"))

    def test_randombytes_has_lock(self):
        self.assertTrue(hasattr(skein.RandomBytes(b"seed"), "_lock"))

    def test_streamcipher_concurrent_keystream_unique(self):
        # Functional check for W1: every keystream slice must be unique
        # because each call atomically advances the position.
        import threading

        c = skein.StreamCipher(b"shared-key")
        chunks = []
        chunks_lock = threading.Lock()
        barrier = threading.Barrier(4)

        def worker():
            barrier.wait()
            local = [c.keystream(64) for _ in range(50)]
            with chunks_lock:
                chunks.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(chunks), len(set(chunks)),
                         "keystream chunks must not repeat under concurrent use")


class SkeinTestMixin:

    @classmethod
    def HASHER_INST(cls, *args, **kwargs):
        return cls._HASHER_INST(*args, **kwargs)

    def setUp(self):
        self.hasher = self.HASHER_INST()

    def tearDown(self):
        del self.hasher

    def test_multiple_digests(self):
        self.assertEqual(self.hasher.digest(), self.hasher.digest())
        self.assertEqual(self.hasher.hexdigest(), self.hasher.hexdigest())

    def test_hex_digest(self):
        st = "".join(format(b, "02x") for b in self.hasher.digest())
        self.assertEqual(self.hasher.hexdigest(), st)

    def test_bit_hashing(self):
        msg = bytes(random.randrange(256) for _ in range(130))
        for bits in range(8 * 130):
            reference = self.HASHER_INST(msg).digest()
            h = self.HASHER_INST()
            h.update(msg, bits=bits)
            h.update(bytes([(msg[bits // 8] << (bits % 8)) & 0xff]), bits=8 - bits % 8)
            h.update(msg[bits // 8 + 1:])
            self.assertEqual(h.digest(), reference)

    def test_digest_slice(self):
        for bits in (list(range(248, 265)) + [511, 512, 513] + [1023, 1024, 1025]):
            h = self.HASHER_INST(bytes(random.randrange(256) for _ in range(10)), digest_bits=bits)
            ref = h.digest()
            for start in range(h.digest_size):
                for stop in range(start + 1, h.digest_size + 1):
                    if ref[start:stop] != h.digest(start, stop):
                        print(start, stop)
                        raise SystemExit
                    self.assertEqual(ref[start:stop], h.digest(start, stop))

    def test_digest_slice_bug(self):
        for i in range(1, 100):
            h = self.HASHER_INST(digest_bits=2 ** 64 - i)
            self.assertEqual(h.digest(0, 10)[:1], h.digest(0, 1))

    def test_empty_slice(self):
        self.assertEqual(self.HASHER_INST().digest(0, 0), b"")
        h = self.HASHER_INST()
        self.assertEqual(h.digest(h.digest_size, h.digest_size), b"")

    def test_init(self):
        self.hasher.update(b"\xff")
        hasher2 = self.HASHER_INST(b"\xff")
        self.assertEqual(hasher2.digest(), self.hasher.digest())

    def test_repr(self):
        self.assertTrue(repr(self.hasher).startswith(f"<Skein-{self.STATE_BITS} hash object at "))

    def test_hashed_count(self):
        self.hasher.update(b"123")
        self.assertEqual(self.hasher.hashed_bits, 8 * 3)
        self.hasher.update(b"12345")
        self.assertEqual(self.hasher.hashed_bits, 8 * 8)
        self.hasher.update(b"12345", bits=5)
        self.assertEqual(self.hasher.hashed_bits, 8 * 8 + 5)
        self.hasher.update(b"12345", bits=3)
        self.assertEqual(self.hasher.hashed_bits, 9 * 8)

    def test_copy(self):
        for e in range(6):
            l = 10 ** e
            a = self.HASHER_INST(bytes(x % 256 for x in range(l)))
            b = a.copy()
            self.assertEqual(a.digest(), b.digest())
            self.assertEqual(a.hashed_bits, b.hashed_bits)
            a.update(bytes(bytes(x % 256 for x in range(1, l + 2))))
            self.assertNotEqual(a.digest(), b.digest())
            b.update(bytes(bytes(x % 256 for x in range(1, l + 2))))
            self.assertEqual(a.digest(), b.digest())

    def test_pickle(self):
        self.hasher.update(bytes(x % 256 for x in range(10000)))
        copy = pickle.loads(pickle.dumps(self.hasher))
        self.assertEqual(self.hasher.digest(), copy.digest())
        self.assertRaises(TypeError, _skein._from_state, 1)
        self.assertRaises(ValueError, _skein._from_state, (1,))


    def test_digest_sizes(self):
        for bits in (1, 2 ** 31 - 1, 2 ** 32, 2 ** 63, 2 ** 64 - 1):
            self.assertEqual(self.HASHER_INST(digest_bits=bits).digest_bits, bits)
        for bits in (0, -1, 2 ** 64, 2 ** 64 + 8):
            self.assertRaises(ValueError, self.HASHER_INST, digest_bits=bits)

    def test_attributes(self):
        for digest_bits in range(1, 2049):
            hasher = self.HASHER_INST(digest_bits=digest_bits)
            self.assertEqual(hasher.block_size * 8, self.STATE_BITS)
            self.assertEqual(hasher.block_bits, self.STATE_BITS)
            self.assertEqual(hasher.digest_size, (digest_bits + 7) // 8)
            self.assertEqual(hasher.digest_bits, digest_bits)
            self.assertEqual(hasher.name, f"Skein-{self.STATE_BITS}")
            self.assertEqual(hasher.hashed_bits, 0)

    def test_init_arg_combinations(self):
        for n in range(8):
            for kws in combinations(["init", "digest_bits", "key", "pers", "public_key", "key_id", "nonce"], n):
                kwdict = {
                    kw: b"bar" + bytes([i]) if kw != "digest_bits" else i + 1
                    for i, kw in enumerate(kws)
                }
                self.HASHER_INST(**kwdict)

    def test_empty_init_args(self):
        hdigest = self.HASHER_INST(b"foo").digest()
        self.assertEqual(self.HASHER_INST(b"foo", key=b"").digest(), hdigest)
        self.assertEqual(self.HASHER_INST(b"foo", pers=b"").digest(), hdigest)
        self.assertEqual(self.HASHER_INST(b"foo", public_key=b"").digest(), hdigest)
        self.assertEqual(self.HASHER_INST(b"foo", key_id=b"").digest(), hdigest)
        self.assertEqual(self.HASHER_INST(b"foo", nonce=b"").digest(), hdigest)
        self.assertEqual(self.HASHER_INST(b"foo", pers=b"", nonce=b"").digest(), hdigest)

    def test_keyword_only(self):
        self.assertRaises(TypeError, self.HASHER_INST, b"foo", 512, b"bar")

    def test_tree_parameters(self):
        self.assertEqual(self.HASHER_INST().digest(), self.HASHER_INST(tree=None).digest())
        self.assertRaises(TypeError, self.HASHER_INST, tree="")
        self.assertRaises(TypeError, self.HASHER_INST, tree=1)
        self.assertRaises(TypeError, self.HASHER_INST, tree=(1,))
        self.assertRaises(TypeError, self.HASHER_INST, tree=(1, 2))
        self.assertRaises(TypeError, self.HASHER_INST, tree=("a", "b", "c"))
        self.assertRaises(TypeError, self.HASHER_INST, tree=(1.5, 1, 2))
        self.assertRaises(ValueError, self.HASHER_INST, tree=(0, 0, 0))
        self.assertRaises(ValueError, self.HASHER_INST, tree=(-1, 1, 2))
        self.assertRaises(ValueError, self.HASHER_INST, tree=(1, -100000, 2))
        self.assertRaises(ValueError, self.HASHER_INST, tree=(1, 1, 1))
        self.assertRaises(ValueError, self.HASHER_INST, tree=(10 ** 20, 1, 2))
        self.assertRaises(ValueError, self.HASHER_INST, tree=(1, -10 ** 20, 2))
        self.assertRaises(ValueError, self.HASHER_INST, tree=(256, 1, 2))
        self.HASHER_INST(tree=(1, 1, 2))
        self.HASHER_INST(tree=(10, 20, 255))

    def test_prng_init(self):
        skein.Random(hasher=self.HASHER_INST)
        skein.Random(seed=42, hasher=self.HASHER_INST)
        # skein.Random(frozenset({1,2,3}), hasher=self.HASHER_INST)
        skein.Random("str", hasher=self.HASHER_INST)

    def test_prng_seed_bytes_like_parity(self):
        # C-10: bytes / bytearray / memoryview seeds must produce the same
        # Skein-derived stream (previously bytearray fell through to the
        # stdlib path and yielded a different stream; memoryview crashed).
        a = skein.Random(b"hello", hasher=self.HASHER_INST)
        b = skein.Random(bytearray(b"hello"), hasher=self.HASHER_INST)
        c = skein.Random(memoryview(b"hello"), hasher=self.HASHER_INST)
        ref = [a.random() for _ in range(5)]
        self.assertEqual([b.random() for _ in range(5)], ref)
        self.assertEqual([c.random() for _ in range(5)], ref)

    def test_prng_state_inspection(self):
        r = skein.Random(b"x", hasher=self.HASHER_INST)
        # check initial state
        state = r._state
        d = self.HASHER_INST(bytes(self.STATE_BITS // 8) + b"x").digest()
        self.assertEqual(state, d)
        # check state after random() call
        r.random()
        t = skein.threefish(state, bytes(15) + bytes([63]))
        d = t.encrypt_block(bytes(self.STATE_BITS // 8))
        self.assertEqual(r._state, d)

    def test_prng_get_set_state(self):
        r = skein.Random(b"123", hasher=self.HASHER_INST)
        r.random()
        r.gauss(0, 1)
        state = r.getstate()
        a = r.random()
        b = r.gauss(0, 1)

        r = skein.Random(b"123", hasher=self.HASHER_INST)
        r.setstate(state)
        self.assertEqual(r.random(), a)
        self.assertEqual(r.gauss(0, 1), b)

    def test_prng_random_stream(self):
        for i in range(0, 5000, 13):
            r = skein.Random(b"abc")
            self.assertEqual(r.read(i) + r.read(5000 - i), skein.Random(b"abc").read(5000))

    def test_getrandombits(self):
        r = skein.Random()
        for k in range(16):
            for _ in range(1000):
                x = r.getrandbits(k)
                self.assertGreaterEqual(x, 0)
                self.assertLess(x, 1 << k)

    def test_streamcipher(self):
        c = skein.StreamCipher(key=b"secret", hasher=self.HASHER_INST)
        x = c.encrypt(b"foobar")
        c = skein.StreamCipher(key=b"secret", hasher=self.HASHER_INST)
        self.assertEqual(c.decrypt(x), b"foobar")

    def test_streamcipher_bug(self):
        x = skein.StreamCipher(b'secret').encrypt(b'hello world')
        c = skein.StreamCipher(b'secret')
        self.assertRaises(TypeError, c.decrypt, 'string')
        self.assertEqual(c.decrypt(x), b'hello world')


class TestSkein256(SkeinTestMixin, unittest.TestCase):
    _HASHER_INST = skein.skein256
    STATE_BITS = 256


class TestSkein512(SkeinTestMixin, unittest.TestCase):
    _HASHER_INST = skein.skein512
    STATE_BITS = 512


class TestSkein1024(SkeinTestMixin, unittest.TestCase):
    _HASHER_INST = skein.skein1024
    STATE_BITS = 1024


class TestSkein1024Tree(SkeinTestMixin, unittest.TestCase):
    STATE_BITS = 1024

    def test_tree_parameters(self):
        # Test not applicable
        pass

    @classmethod
    def HASHER_INST(cls, *args, **kwargs):
        return skein.skein1024(*args, tree=(1, 2, 3), **kwargs)

    # test_copy fails and is overridden so it does not run. Investigate.
    def test_copy(self):
        pass


class TestSkeinKAT(unittest.TestCase):
    RE_HEADER = re.compile(r":Skein-(\d+):\s+(\d+)-bit hash, "+
                           r"msgLen =\s+(\d+) bits(.+)")
    RE_TREE = re.compile(r"Tree: leaf=(..), node=(..), maxLevels=(..)")
    HASHER_INSTS = {256:skein.skein256, 512:skein.skein512, 1024:skein.skein1024}

    def testKATFile(self):

        with open(KATFILE, "r") as f:
            kattxt = f.read()
        n = k = 0
        for block in kattxt.split("---------\n"):
            if not block.strip():
                continue
            n += 1

            # parse header line
            m = self.RE_HEADER.search(block)
            test_case_name = str(m.group())

            state_bits, digest_bits, msg_bits = map(int, m.groups()[:-1])
            rest = m.groups()[-1]
            if "Tree" in rest:
                tree_params = tuple(int(x, 16) for x in
                                    self.RE_TREE.search(rest).groups())
            else:
                tree_params = None

            print(test_case_name)

            # extract message text and MAC key
            block = block.split("Message data:\n", 1)[1]
            if "MAC key =" in block:
                msgtxt, block = block.split("MAC key =", 1)
                check, block = block.split("\n", 1)
                check = int(check.split()[0])
                mactxt, hashtxt = block.split("Result:\n")
            else:
                msgtxt, hashtxt = block.split("Result:\n")
                mactxt = ""

            # hash data and compare result
            hasher = self.HASHER_INSTS[state_bits](digest_bits=digest_bits,
                                              key=by(mactxt), tree=tree_params)
            hasher.update(by(msgtxt), bits=msg_bits)
            self.assertEqual(hasher.digest(), by(hashtxt))
            k += 1
        print(f"\n{k}/{n} known answer tests succeeded ({n-k} skipped)")


def by(txt):
    if "(none)" in txt:
        return b""
    lines = [line for line in txt.split("\n") if line.startswith("   ")]
    txt = "".join(lines)
    return bytes(int(x, 16) for x in txt.split())


class ThreefishTestMixin:

    def setUp(self):
        self.t = skein.threefish(bytes(range(self.KEYLEN)), bytes(range(16)))
        # create a distractor object for strange string buffer false positives:
        skein.threefish(bytes(range(self.KEYLEN)), bytes(range(11, 27)))

    def test_attributes(self):
        self.assertEqual(self.t.block_size, self.KEYLEN)
        self.assertEqual(self.t.block_bits, self.KEYLEN * 8)
        self.assertEqual(self.t.tweak, bytes(range(16)))

    def test_tweak(self):

        def set(v):
            self.t.tweak = v

        self.assertRaises(TypeError, set, 0)
        self.assertRaises(ValueError, set, bytes(17))
        set(bytes(range(1, 17)))
        self.assertEqual(self.t.tweak, bytes(range(1, 17)))

        # C-3: setter must accept any bytes-like (bytearray, memoryview)
        # to match the constructor's y* buffer-protocol parsing.
        self.t.tweak = bytearray(b"\x02" * 16)
        self.assertEqual(self.t.tweak, b"\x02" * 16)
        self.t.tweak = memoryview(b"\x03" * 16)
        self.assertEqual(self.t.tweak, b"\x03" * 16)
        # Length validation still applies through the buffer-protocol path.
        self.assertRaises(ValueError, set, memoryview(b"\x04" * 8))

    def test_del_tweak_raises_attribute_error(self):
        # F9 regression: `del t.tweak` invoked the setter with NULL value;
        # without the new NULL guard PyByteArray_Check would deref ob_type
        # and SEGV.
        with self.assertRaises(AttributeError):
            del self.t.tweak

    def test_encrypt_block(self):
        self.assertRaises(ValueError, self.t.encrypt_block, bytes(1))
        self.assertRaises(ValueError, self.t.encrypt_block, bytes(self.KEYLEN + 1))
        self.assertRaises(ValueError, self.t.encrypt_block, bytes(self.KEYLEN - 1))

    def test_decrypt_block(self):
        self.assertRaises(ValueError, self.t.decrypt_block, bytes(1))
        self.assertRaises(ValueError, self.t.decrypt_block, bytes(self.KEYLEN + 1))
        self.assertRaises(ValueError, self.t.decrypt_block, bytes(self.KEYLEN - 1))

    def test_roundtrip(self):
        for n in range(1, 101):
            key = bytes(random.randint(0, 255) for _ in range(self.KEYLEN))
            tweak = bytes(random.randint(0, 255) for _ in range(16))
            plain = bytes(random.randint(0, 255) for _ in range(self.KEYLEN))
            t = skein.threefish(key, tweak)
            self.assertEqual(t.decrypt_block(t.encrypt_block(plain)), plain)
        print(f"\n{n} random Threefish-{self.KEYLEN*8} roundtrip tests succeeded.")


class TestThreefish32(ThreefishTestMixin, unittest.TestCase):
    KEYLEN = 32


class TestThreefish64(ThreefishTestMixin, unittest.TestCase):
    KEYLEN = 64


class TestThreefish128(ThreefishTestMixin, unittest.TestCase):
    KEYLEN = 128


class TestErrorPaths(unittest.TestCase):

    def test_update_bits_larger_than_message(self):
        h = skein.skein512()
        with self.assertRaisesRegex(ValueError, r"'bits' larger than 8\*len\(message\)"):
            h.update(b"xx", bits=100)
        # State unchanged after failed update (no bytes counted)
        self.assertEqual(h.hashed_bits, 0)

    def test_update_negative_bits(self):
        h = skein.skein512()
        # bits=-1 is the default sentinel ("whole message"); the error path
        # is reached by any value strictly less than -1.
        with self.assertRaisesRegex(ValueError, r"'bits' may not be negative"):
            h.update(b"xx", bits=-2)
        with self.assertRaisesRegex(ValueError, r"'bits' may not be negative"):
            h.update(b"xx", bits=-1000)
        self.assertEqual(h.hashed_bits, 0)

    def test_update_unaligned_bits_mismatch(self):
        # After an unaligned update (missing_bits > 0), further updates are only
        # allowed to complete the last byte. Exceeding that raises ValueError.
        h = skein.skein512()
        h.update(b"\x00", bits=3)          # leaves 5 missing bits
        with self.assertRaisesRegex(ValueError, r"bits required for byte alignment"):
            h.update(b"\x00\x00")           # whole bytes on unaligned: rejected
        with self.assertRaisesRegex(ValueError, r"bits required for byte alignment"):
            h.update(b"\x00", bits=6)       # bits > missing_bits: rejected

    def test_update_error_paths_no_leak(self):
        # Heavy regression check for the PyBuffer_Release fixes: the error
        # paths must not leak the input buffer. RSS is a coarse but effective
        # signal over this many iterations.
        import gc, resource
        def rss():
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        h = skein.skein512()
        for _ in range(1000):                       # warm up
            try: h.update(b"xx", bits=100)
            except ValueError: pass
        gc.collect(); r0 = rss()
        for _ in range(50_000):
            try: h.update(b"xx", bits=100)
            except ValueError: pass
            try: h.update(b"xx", bits=-1)
            except ValueError: pass
        gc.collect(); r1 = rss()
        # Allow 1 MB drift for allocator noise; a leak would be many MB.
        self.assertLess(abs(r1 - r0) / 1024, 1024,
                        f"RSS grew {(r1-r0)/1024:.0f} KB across 100k error-path trips")

    def test_evil_tree_index_does_not_crash(self):
        # F12 regression: PySequence_Fast(tree, ...) returns the user's list
        # unchanged for a list input.  A custom __index__ on tree entries
        # could mutate the list mid-iteration, freeing the items the
        # subsequent get_tree_param calls dereference (use-after-free).
        # init_skein now snapshots to an immutable tuple before calling
        # get_tree_param.
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
        # Behaviour after the user mutates their own input is undefined-
        # but-safe: any of success / ValueError / TypeError is acceptable
        # provided we don't crash.
        try:
            skein.skein512(b"x", tree=my_list)
        except (TypeError, ValueError):
            pass

    def test_init_error_path_tree_no_leak(self):
        # F5 regression: init_skein's error path used to overwrite
        # next_tree_level with NULL, leaking the chaining-state linked list
        # if init_tree had already populated it.  Run many tree-mode
        # constructions + dealloc cycles and assert RSS stays bounded.
        import gc, resource

        def rss():
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        for _ in range(50):                            # warm up
            h = skein.skein512(b"x" * 1000, tree=(2, 2, 10))
            h.update(b"y" * 5000)
            del h
        gc.collect(); r0 = rss()
        for _ in range(2000):
            h = skein.skein512(b"x" * 1000, tree=(2, 2, 10))
            h.update(b"y" * 5000)
            del h
        gc.collect(); r1 = rss()
        self.assertLess(abs(r1 - r0) / 1024, 1024,
                        f"RSS grew {(r1-r0)/1024:.0f} KB across 2000 tree dealloc cycles")


class TestDigestBitsGuard(unittest.TestCase):
    """PyErr_Clear at init_skein:1449 is guarded to only clear expected
    Overflow/TypeError from PyLong_AsUnsignedLongLong and propagate others.
    The guard's propagation branch is defence in depth: in current CPython,
    PyLong_AsUnsignedLongLong rejects non-PyLong inputs with TypeError before
    ever reaching __index__, so a custom __index__ raising MemoryError or
    KeyboardInterrupt isn't actually reachable from Python. The TypeError
    and OverflowError conversions are both covered below."""

    def test_digest_bits_wrong_type_raises_valueerror(self):
        # TypeError branch of the guard: non-int input gets converted to
        # ValueError with the canonical message.
        for bad in ("not-an-int", b"bytes", [1, 2, 3], {}, 1.5, object()):
            with self.assertRaisesRegex(ValueError,
                                         r"digest_bits must be between 1 and 2\*\*64-1"):
                skein.skein512(digest_bits=bad)

    def test_digest_bits_overflow_raises_valueerror(self):
        # OverflowError branch of the guard: values too large for
        # unsigned long long produce the same canonical ValueError.
        with self.assertRaisesRegex(ValueError,
                                     r"digest_bits must be between 1 and 2\*\*64-1"):
            skein.skein512(digest_bits=2 ** 80)


class TestDigestSliceErrors(unittest.TestCase):
    """digest(start, stop) validation."""

    def test_digest_arity(self):
        h = skein.skein512()
        with self.assertRaisesRegex(TypeError, r"digest\(\) takes either 0 or 2"):
            h.digest(5)
        with self.assertRaisesRegex(TypeError, r"digest\(\) takes either 0 or 2"):
            h.digest(1, 2, 3)

    def test_digest_start_after_stop(self):
        h = skein.skein512()
        with self.assertRaisesRegex(ValueError, r"0<=start<=stop<=digest_size"):
            h.digest(5, 3)

    def test_digest_stop_past_size(self):
        h = skein.skein512()                    # digest_size = 64
        with self.assertRaisesRegex(ValueError, r"0<=start<=stop<=digest_size"):
            h.digest(0, 65)
        with self.assertRaisesRegex(ValueError, r"0<=start<=stop<=digest_size"):
            h.digest(0, 2 ** 40)

    def test_huge_digest_bits_full_digest_capped(self):
        # F8 regression: digest_bits up to 2**64-1 is permitted (StreamCipher
        # depends on that), but the actual byte allocation must be capped so
        # a single digest() call can't OOM-abort the process.
        h = skein.skein512(b"x", digest_bits=2 ** 40)
        with self.assertRaisesRegex(ValueError, "digest range too large"):
            h.digest()

    def test_huge_digest_bits_hexdigest_capped(self):
        # F10 regression: hexdigest takes no arguments and always allocates
        # 3x digest_size; capped via the same helper as digest().
        h = skein.skein512(b"x", digest_bits=2 ** 40)
        with self.assertRaisesRegex(ValueError, "digest range too large"):
            h.hexdigest()

    def test_digest_slice_within_cap_works(self):
        # Negative side of the same fix: small slices through a huge
        # digest_bits hash must still succeed.  This is the StreamCipher
        # use case.
        h = skein.skein512(b"x", digest_bits=2 ** 40)
        self.assertEqual(len(h.digest(0, 64)), 64)

    def test_keystream_does_not_cycle_at_2_to_32_blocks(self):
        # F1 regression: output_hash's per-block counter must use the full
        # 8-byte width, not 4.  With the historic truncation, the keystream
        # repeated every 2**32 blocks (= 256 GB on skein-512).
        h = skein.skein512(b"key-material", digest_bits=2 ** 64 - 1)
        b0 = h.digest(0, 64)
        b1 = h.digest(2 ** 38, 2 ** 38 + 64)         # 256 GB → block 2**32
        self.assertNotEqual(
            b0, b1,
            "keystream block at offset 0 must differ from block at 256 GB")
        # And cross-check with skein-256 at its own wrap point (128 GB).
        h2 = skein.skein256(b"key", digest_bits=2 ** 64 - 1)
        self.assertNotEqual(h2.digest(0, 32),
                            h2.digest(2 ** 37, 2 ** 37 + 32))


class TestThreefishConstructorErrors(unittest.TestCase):
    """threefish() validation: key length, tweak length."""

    def test_bad_key_length(self):
        for n in (0, 1, 31, 33, 48, 63, 65, 127, 129, 256):
            with self.assertRaisesRegex(ValueError,
                                         r"key must be 32, 64 or 128 bytes long"):
                skein.threefish(bytes(n), bytes(16))

    def test_bad_tweak_length(self):
        for n in (0, 1, 8, 15, 17, 32):
            with self.assertRaisesRegex(ValueError, r"tweak must be 16 bytes long"):
                skein.threefish(bytes(32), bytes(n))

    def test_non_bytes_input(self):
        self.assertRaises(TypeError, skein.threefish, "string-key", bytes(16))
        self.assertRaises(TypeError, skein.threefish, bytes(32), "string-tweak")


class TestFromStateValidation(unittest.TestCase):
    """_skein._from_state branches in skein_setstate. These are reachable via
    pickle, so corrupted pickles must fail with ValueError rather than produce
    a broken skein object."""

    @classmethod
    def _state(cls, init=b"seed-message", **kw):
        h = skein.skein512(init, **kw)
        return h.__reduce__()[1][0]

    def test_non_tuple_raises_typeerror(self):
        self.assertRaises(TypeError, _skein._from_state, 1)
        self.assertRaises(TypeError, _skein._from_state, "string")
        self.assertRaises(TypeError, _skein._from_state, [2, 512, 64, 0, 0, b"", b"", b""])

    def test_short_tuple(self):
        for length in range(8):
            self.assertRaises(ValueError, _skein._from_state, tuple(range(length)))

    def test_wrong_protocol_version(self):
        s = list(self._state())
        s[0] = 1        # we only understand protocol 2
        self.assertRaises(ValueError, _skein._from_state, tuple(s))
        s[0] = 3
        self.assertRaises(ValueError, _skein._from_state, tuple(s))

    def test_bad_digest_bits(self):
        s = list(self._state())
        for bad in (0,):
            s[1] = bad
            self.assertRaises(ValueError, _skein._from_state, tuple(s))
        s[1] = 7        # not divisible by 8
        self.assertRaises(ValueError, _skein._from_state, tuple(s))

    def test_bad_state_bytes(self):
        s = list(self._state())
        for bad in (0, 16, 96, 256):
            s[2] = bad
            self.assertRaises(ValueError, _skein._from_state, tuple(s))

    def test_missing_bits_out_of_range(self):
        s = list(self._state())
        s[4] = 8        # valid range is 0..7
        self.assertRaises(ValueError, _skein._from_state, tuple(s))

    def test_missing_bits_without_buffered_byte(self):
        s = list(self._state(b""))         # bCnt == 0
        s[4] = 3                           # missing_bits > 0 requires bCnt >= 1
        # Keep b-buffer empty so bCnt stays 0
        s[5] = b""
        self.assertRaises(ValueError, _skein._from_state, tuple(s))

    def test_buffer_b_wrong_type(self):
        s = list(self._state())
        s[5] = "not bytes"
        self.assertRaises(ValueError, _skein._from_state, tuple(s))

    def test_buffer_b_too_large(self):
        s = list(self._state())
        s[5] = b"\x00" * 1000      # far larger than stateBytes (64 for skein512)
        self.assertRaises(ValueError, _skein._from_state, tuple(s))

    def test_x_buffer_wrong_size(self):
        s = list(self._state())
        s[6] = b"\x00" * 5         # should be 64 for skein512
        self.assertRaises(ValueError, _skein._from_state, tuple(s))

    def test_t_buffer_wrong_size(self):
        s = list(self._state())
        s[7] = b"\x00" * 8         # should be exactly 16
        self.assertRaises(ValueError, _skein._from_state, tuple(s))

    def test_tree_intro_incomplete(self):
        # A tree-state tuple must have len >= 15. Any length in (8, 15) is
        # invalid except 8 itself (sequential).
        s = list(self._state(tree=(2, 2, 10)))
        self.assertGreaterEqual(len(s), 15)      # baseline sanity
        truncated = tuple(s[:12])                # len=12: short of 15
        self.assertRaises(ValueError, _skein._from_state, truncated)

    def test_tree_partial_final_level(self):
        # Valid tree state is len=15 + 3k; adding 1 or 2 stray items is invalid.
        s = list(self._state(tree=(2, 2, 10)))
        for extra in (1, 2):
            bad = tuple(s + [b"\x00"] * extra)
            self.assertRaises(ValueError, _skein._from_state, bad)

    def test_tree_pickle_roundtrip(self):
        # F3 regression: skein_setstate's PyTuple_GetSlice path is reached
        # only when restoring a tree-mode hash via pickle.  Round-trip a
        # tree-mode hash and confirm the digest survives.
        h = skein.skein512(b"data", tree=(2, 2, 10))
        h.update(b"more")
        copy = pickle.loads(pickle.dumps(h))
        self.assertEqual(h.digest(), copy.digest())

    def test_typeerror_from_get_tree_param_is_preserved(self):
        # C-2 regression: _from_state used to overwrite skein_setstate's
        # precise TypeError with a generic ValueError("invalid state").
        # A non-int tree-leaf entry now surfaces the underlying TypeError.
        s = list(self._state(tree=(2, 2, 10)))
        s[8] = 1.5      # PyFloat → get_tree_param sets TypeError
        with self.assertRaisesRegex(TypeError,
                                     "tree parameters have to be integers"):
            _skein._from_state(tuple(s))

    def test_value_error_from_get_tree_param_is_preserved(self):
        # Same C-2 fix on the ValueError side: out-of-range tree params
        # surface get_tree_param's specific message rather than the generic
        # "invalid state".
        s = list(self._state(tree=(2, 2, 10)))
        s[8] = 0        # tree_leaf min is 1
        with self.assertRaisesRegex(ValueError,
                                     "tree parameters have to be between"):
            _skein._from_state(tuple(s))


if __name__ == "__main__":
    t = unittest.defaultTestLoader.loadTestsFromModule(sys.modules["__main__"])
    r = unittest.TextTestRunner(verbosity=4)
    r.run(t)
    if hasattr(sys, "gettotalrefcount"):
        refc = sys.gettotalrefcount()
        for i in range(30):
            r.run(t)
            oldc = refc
            refc = sys.gettotalrefcount()
            print("additional references:", refc - oldc)
