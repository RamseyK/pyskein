import sys
import re
import random
import unittest
import warnings
import pickle
from itertools import combinations, chain
from functools import partial
from binascii import unhexlify

import skein, _skein

KATFILE = "skein_golden_kat.txt"


class TestSkeinModule(unittest.TestCase):
    def test(self):
        self.assertEqual(type(skein.__version__), str)
        self.assert_(type(skein.skein256())
                     is type(skein.skein512())
                     is type(skein.skein1024()))


class TestSkeinBase:
    def setUp(self):
        self.hasher = self.HASHER()

    def tearDown(self):
        del self.hasher

    def testMultipleDigests(self):
        self.assertEqual(self.hasher.digest(), self.hasher.digest())
        self.assertEqual(self.hasher.hexdigest(), self.hasher.hexdigest())

    def testHexDigest(self):
        st = "".join(format(b, "02x") for b in self.hasher.digest())
        self.assertEqual(self.hasher.hexdigest(), st)

    def testBitHashing(self):
        msg = bytes(random.randrange(256) for _ in range(130))
        for bits in range(8*130):
            reference = self.HASHER(msg).digest()
            h = self.HASHER()
            h.update(msg, bits=bits)
            h.update(bytes([(msg[bits//8]<<(bits%8))&0xff]), bits=8-bits%8)
            h.update(msg[bits//8+1:])
            self.assertEqual(h.digest(), reference)

    def testDigestSlice(self):
        for bits in (list(range(248,265))+[511, 512, 513]+[1023, 1024, 1025]):
            h = self.HASHER(bytes(random.randrange(256) for _ in range(10)),
                            digest_bits=bits)
            ref = h.digest()
            for start in range(h.digest_size):
                for stop in range(start+1, h.digest_size+1):
                    if ref[start:stop] != h.digest(start, stop):
                        print(start, stop)
                        raise SystemExit
                    self.assertEqual(ref[start:stop], h.digest(start, stop))

    def testDigestSliceBug(self):
        for i in range(1, 100):
            h = self.HASHER(digest_bits=2**64-i)
            self.assertEqual(h.digest(0, 10)[:1], h.digest(0, 1))

    def testEmptySlice(self):
        self.assertEqual(self.HASHER().digest(0, 0), b"")
        h = self.HASHER()
        self.assertEqual(h.digest(h.digest_size, h.digest_size), b"")

    def testInit(self):
        self.hasher.update(b"\xff")
        hasher2 = self.HASHER(b"\xff")
        self.assertEqual(hasher2.digest(), self.hasher.digest())

    def testRepr(self):
        self.assert_(repr(self.hasher).startswith("<Skein-%s hash object at "
                                                  % self.STATE_BITS))

    def testHashedCount(self):
        self.hasher.update(b"123")
        self.assertEqual(self.hasher.hashed_bits, 8*3)
        self.hasher.update(b"12345")
        self.assertEqual(self.hasher.hashed_bits, 8*8)
        self.hasher.update(b"12345", bits=5)
        self.assertEqual(self.hasher.hashed_bits, 8*8+5)
        self.hasher.update(b"12345", bits=3)
        self.assertEqual(self.hasher.hashed_bits, 9*8)

    def testCopy(self):
        for e in range(6):
            l = 10**e
            a = self.HASHER(bytes(x%256 for x in range(l)))
            b = a.copy()
            self.assertEqual(a.digest(), b.digest())
            self.assertEqual(a.hashed_bits, b.hashed_bits)
            a.update(bytes(bytes(x%256 for x in range(1, l+2))))
            self.assertNotEqual(a.digest(), b.digest())
            b.update(bytes(bytes(x%256 for x in range(1, l+2))))
            self.assertEqual(a.digest(), b.digest())

    def testPickle(self):
        self.hasher.update(bytes(x%256 for x in range(10000)))
        copy = pickle.loads(pickle.dumps(self.hasher))
        self.assertEqual(self.hasher.digest(), copy.digest())
        self.assertRaises(TypeError, _skein._from_state, 1)
        self.assertRaises(ValueError, _skein._from_state, (1,))

    def testDigestSizes(self):
        for bits in (1, 2**31-1, 2**32, 2**63, 2**64-1):
            self.assertEqual(self.HASHER(digest_bits=bits).digest_bits, bits)
        for bits in (0, -1, 2**64, 2**64+8):
            self.assertRaises(ValueError, self.HASHER, digest_bits=bits)

    def testAttributes(self):
        for digest_bits in range(1, 2049):
            hasher = self.HASHER(digest_bits=digest_bits)
            self.assertEqual(hasher.block_size*8, self.STATE_BITS)
            self.assertEqual(hasher.block_bits, self.STATE_BITS)
            self.assertEqual(hasher.digest_size, (digest_bits+7)//8)
            self.assertEqual(hasher.digest_bits, digest_bits)
            self.assertEqual(hasher.name, "Skein-{0}".format(self.STATE_BITS))
            self.assertEqual(hasher.hashed_bits, 0)

    def testInitArgCombinations(self):
        for n in range(8):
            for kws in combinations(["init", "digest_bits", "key", "pers",
                                     "public_key", "key_id", "nonce"], n):
                kwdict = {kw:b"bar"+bytes([i]) if kw != "digest_bits" else i+1
                          for i, kw in enumerate(kws)}
                self.HASHER(**kwdict)

    def testEmptyInitArgs(self):
        hash = self.HASHER(b"foo").digest()
        self.assertEqual(self.HASHER(b"foo", key=b"").digest(), hash)
        self.assertEqual(self.HASHER(b"foo", pers=b"").digest(), hash)
        self.assertEqual(self.HASHER(b"foo", public_key=b"").digest(), hash)
        self.assertEqual(self.HASHER(b"foo", key_id=b"").digest(), hash)
        self.assertEqual(self.HASHER(b"foo", nonce=b"").digest(), hash)
        self.assertEqual(self.HASHER(b"foo", pers=b"", nonce=b"").digest(),
                         hash)

    def testKeywordOnly(self):
        self.assertRaises(TypeError, self.HASHER, b"foo", 512, b"bar")

    def testTreeParameters(self):
        self.assertEqual(self.HASHER().digest(),
                         self.HASHER(tree=None).digest())
        self.assertRaises(TypeError, self.HASHER, tree="")
        self.assertRaises(TypeError, self.HASHER, tree=1)
        self.assertRaises(TypeError, self.HASHER, tree=(1,))
        self.assertRaises(TypeError, self.HASHER, tree=(1, 2))
        self.assertRaises(TypeError, self.HASHER, tree=("a", "b", "c"))
        self.assertRaises(TypeError, self.HASHER, tree=(1.5, 1, 2))
        self.assertRaises(ValueError, self.HASHER, tree=(0, 0, 0))
        self.assertRaises(ValueError, self.HASHER, tree=(-1, 1, 2))
        self.assertRaises(ValueError, self.HASHER, tree=(1, -100000, 2))
        self.assertRaises(ValueError, self.HASHER, tree=(1, 1, 1))
        self.assertRaises(ValueError, self.HASHER, tree=(10**20, 1, 2))
        self.assertRaises(ValueError, self.HASHER, tree=(1, -10**20, 2))
        self.assertRaises(ValueError, self.HASHER, tree=(256, 1, 2))
        self.HASHER(tree=(1, 1, 2))
        self.HASHER(tree=(10, 20, 255))

    def testPRNGInit(self):
        skein.Random(hasher=self.HASHER)
        skein.Random(seed=42, hasher=self.HASHER)
        skein.Random(frozenset({1,2,3}), hasher=self.HASHER)
        skein.Random("str", hasher=self.HASHER)

    def testPRNGStateInspection(self):
        r = skein.Random(b"x", hasher=self.HASHER)
        # check initial state
        state = r._state
        d = self.HASHER(bytes(self.STATE_BITS//8)+b"x").digest()
        self.assertEqual(state, d)
        # check state after random() call
        r.random()
        t = skein.threefish(state, bytes(15)+bytes([63]))
        d = t.encrypt_block(bytes(self.STATE_BITS//8))
        self.assertEqual(r._state, d)

    def testPRNGGetSetState(self):
        r = skein.Random(b"123", hasher=self.HASHER)
        r.random()
        r.gauss(0, 1)
        state = r.getstate()
        a = r.random()
        b = r.gauss(0, 1)

        r = skein.Random(b"123", hasher=self.HASHER)
        r.setstate(state)
        self.assertEqual(r.random(), a)
        self.assertEqual(r.gauss(0, 1), b)

    def testPRNGRandomStream(self):
        for i in range(0, 5000, 13):
            r = skein.Random(b"abc")
            self.assertEqual(r.read(i)+r.read(5000-i),
                             skein.Random(b"abc").read(5000))

    def test_getrandombits(self):
        r = skein.Random()
        for k in range(16):
            for _ in range(1000):
                x = r.getrandbits(k)
                self.assertGreaterEqual(x, 0)
                self.assertLess(x, 1<<k)

    def testStreamCipher(self):
        c = skein.StreamCipher(key=b"secret", hasher=self.HASHER)
        x = c.encrypt(b"foobar")
        c = skein.StreamCipher(key=b"secret", hasher=self.HASHER)
        self.assertEqual(c.decrypt(x), b"foobar")

    def testStreamCipherBug(self):
        x = skein.StreamCipher(b'secret').encrypt(b'hello world')
        c = skein.StreamCipher(b'secret')
        self.assertRaises(TypeError, c.decrypt, 'string')
        self.assertEqual(c.decrypt(x), b'hello world')


class TestSkein256(TestSkeinBase, unittest.TestCase):
    HASHER = skein.skein256
    STATE_BITS = 256

class TestSkein512(TestSkeinBase, unittest.TestCase):
    HASHER = skein.skein512
    STATE_BITS = 512

class TestSkein1024(TestSkeinBase, unittest.TestCase):
    HASHER = skein.skein1024
    STATE_BITS = 1024

class TestSkein1024Tree(TestSkeinBase, unittest.TestCase):
    HASHER = partial(skein.skein1024, tree=(1, 2, 3))
    STATE_BITS = 1024
    def testTreeParameters(self): pass


class TestSkeinKAT(unittest.TestCase):
    RE_HEADER = re.compile(r":Skein-(\d+):\s+(\d+)-bit hash, "+
                           r"msgLen =\s+(\d+) bits(.+)")
    RE_TREE = re.compile(r"Tree: leaf=(..), node=(..), maxLevels=(..)")
    HASHERS = {256:skein.skein256, 512:skein.skein512, 1024:skein.skein1024}

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
            state_bits, digest_bits, msg_bits = map(int, m.groups()[:-1])
            rest = m.groups()[-1]
            if "Tree" in rest:
                tree_params = tuple(int(x, 16) for x in
                                    self.RE_TREE.search(rest).groups())
            else:
                tree_params = None

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
            hasher = self.HASHERS[state_bits](digest_bits=digest_bits,
                                              key=by(mactxt), tree=tree_params)
            hasher.update(by(msgtxt), bits=msg_bits)
            self.assertEqual(hasher.digest(), by(hashtxt))
            k += 1
        print("\n{0}/{1} known answer tests succeeded ({2} skipped)".format(
              k, n, n-k))


def by(txt):
    if "(none)" in txt:
        return bytes()
    lines = [line for line in txt.split("\n") if line.startswith("   ")]
    txt = "".join(lines)
    return bytes(int(x, 16) for x in txt.split())


class TestThreefishBase:
    def setUp(self):
        self.t = skein.threefish(bytes(range(self.KEYLEN)),
                                 bytes(range(16)))
        # create a distractor object for strange string buffer false positives:
        skein.threefish(bytes(range(self.KEYLEN)), bytes(range(11, 27)))

    def test_attributes(self):
        self.assertEqual(self.t.block_size, self.KEYLEN)
        self.assertEqual(self.t.block_bits, self.KEYLEN*8)
        self.assertEqual(self.t.tweak, bytes(range(16)))

    def test_tweak(self):
        def set(v):
            self.t.tweak = v
        self.assertRaises(TypeError, set, 0)
        self.assertRaises(ValueError, set, bytes(17))
        set(bytes(range(1, 17)))
        self.assertEqual(self.t.tweak, bytes(range(1, 17)))

    def test_encrypt_block(self):
        self.assertRaises(ValueError,
                          self.t.encrypt_block, bytes(1))
        self.assertRaises(ValueError,
                          self.t.encrypt_block, bytes(self.KEYLEN+1))
        self.assertRaises(ValueError,
                          self.t.encrypt_block, bytes(self.KEYLEN-1))

    def test_decrypt_block(self):
        self.assertRaises(ValueError,
                          self.t.decrypt_block, bytes(1))
        self.assertRaises(ValueError,
                          self.t.decrypt_block, bytes(self.KEYLEN+1))
        self.assertRaises(ValueError,
                          self.t.decrypt_block, bytes(self.KEYLEN-1))

    def test_roundtrip(self):
        for n in range(1, 101):
            key = bytes(random.randint(0, 255) for _ in range(self.KEYLEN))
            tweak = bytes(random.randint(0, 255) for _ in range(16))
            plain = bytes(random.randint(0, 255) for _ in range(self.KEYLEN))
            t = skein.threefish(key, tweak)
            self.assertEqual(t.decrypt_block(t.encrypt_block(plain)), plain)
        print("\n{0} random Threefish-{1} roundtrip tests succeeded.".format(
              n, self.KEYLEN*8))

class TestThreefish32(TestThreefishBase, unittest.TestCase):
    KEYLEN = 32

class TestThreefish64(TestThreefishBase, unittest.TestCase):
    KEYLEN = 64

class TestThreefish128(TestThreefishBase, unittest.TestCase):
    KEYLEN = 128


if __name__ == "__main__":
    t = unittest.defaultTestLoader.loadTestsFromModule(sys.modules["__main__"])
    r = unittest.TextTestRunner()
    r.run(t)
    if hasattr(sys, "gettotalrefcount"):
        refc = sys.gettotalrefcount()
        for i in range(30):
            r.run(t)
            oldc = refc
            refc = sys.gettotalrefcount()
            print("additional references:", refc-oldc)
