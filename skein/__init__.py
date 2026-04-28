# __init__.py
# Copyright 2009, 2010, 2011, 2012, 2013 Hagen Fürstenau <hagen@zhuliguan.net>
#
# This file is part of PySkein.
#
# PySkein is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


###
### Skein-PRNG ###
###
import random
import threading

from _skein import skein256, skein512, skein1024, threefish  # noqa


class Random(random.Random):
    _BPF = random.BPF
    _RECIP_BPF = random.RECIP_BPF
    # _TWEAK: 16-byte Threefish tweak whose last byte is 0x3f = 63, the
    # numeric value of SKEIN_BLOCK_TYPE_OUT.  Using the output-type tweak
    # ties this PRNG to Skein's counter-mode output stage (spec §2.3),
    # ensuring its keystream is domain-separated from other Threefish uses.
    _TWEAK = bytes(15) + b"\x3f"
    _random = random

    def __init__(self, seed=None, hasher=skein512):
        """Initialize SkeinRandom instance.

        - 'seed' as in method seed().
        - 'hasher' may be skein256, skein512, or skein1024.
        """
        # RLock not Lock: getrandbits() calls read() which would self-deadlock
        # on a plain Lock.  Set before super().__init__() because that calls
        # self.seed(), which acquires the lock.
        self._lock = threading.RLock()
        self._hasher = hasher
        self._state_bytes = hasher().block_size
        self._state = bytes(self._state_bytes)
        # Two fixed counter blocks: 0x00…00 and 0x01 00…00 (little-endian 0
        # and 1).  Encrypting both under the same Threefish key (state) yields
        # two independent output blocks per state advance, doubling throughput
        # without an extra key derivation step.
        self._counter0 = bytes(self._state_bytes)
        self._counter1 = b"\1" + bytes(self._state_bytes - 1)
        super().__init__(seed)

    def seed(self, seed=None):
        """Initialize internal state from hashable object.

        If seed is a bytes object, set state according to Skein specification.
        Otherwise derive a bytes object from the seed using random.Random.
        """

        if isinstance(seed, (bytes, bytearray, memoryview)):
            seed = bytes(seed)
        elif seed is not None:
            r = self._random.Random(seed)
            seed = bytes(r.randrange(256) for _ in range(self._state_bytes))
        else:
            seed = bytes(self._state_bytes)

        with self._lock:
            # Mix the new seed into the existing state via Skein rather than
            # replacing it outright, so seeding can be called multiple times to
            # accumulate entropy without resetting the PRNG to a known state.
            self._state = self._hasher(self._state + seed).digest()
            self._buffer = b""
            self._number = 0
            self._bits = 0

    def read(self, n: int):
        """Return n random bytes.

        The stream of random bytes is reproducible for a given seed:

        >>> r = Random(seed)
        >>> assert r.read(m)+r.read(n) == Random(seed).read(m+n)
        """
        if n < 0:
            raise ValueError("number of random bytes needs to be >= 0")
        with self._lock:
            if len(self._buffer) < n:
                chunks = [self._buffer]
                blocks = ((n - len(self._buffer) - 1) // self._state_bytes) + 1
                for _ in range(1, blocks + 1):
                    # Each iteration uses the current state as the Threefish key.
                    # Encrypting counter0 produces the next state (advancing the
                    # internal RNG); encrypting counter1 produces output bytes.
                    # This two-block scheme keeps state and output derivation
                    # independent, preventing an observer of output from recovering
                    # the state.
                    output = threefish(self._state, self._TWEAK).encrypt_block
                    self._state = output(self._counter0)
                    chunks.append(output(self._counter1))
                self._buffer = b"".join(chunks)
                assert len(self._buffer) >= n
            res, self._buffer = self._buffer[:n], self._buffer[n:]
        return res

    def getrandbits(self, k):
        """Return an int with k random bits"""
        with self._lock:
            bits = self._bits
            for b in self.read((k - self._bits - 1) // 8 + 1):
                self._number |= b << bits
                bits += 8
            r = self._number & ((1 << k) - 1)
            self._number >>= k
            self._bits = bits - k
        return r

    def random(self):
        """Get the next random number in the range [0.0, 1.0)"""
        with self._lock:
            return self.getrandbits(self._BPF) * self._RECIP_BPF

    def getstate(self):
        """Return internal state; can be passed to setstate() later."""
        with self._lock:
            return (self._state, self._buffer, self._number, self._bits, self.gauss_next)

    def setstate(self, state):
        """Restore internal state from object returned by getstate()."""
        with self._lock:
            (self._state, self._buffer, self._number, self._bits, self.gauss_next) = state


del random


class RandomBytes:
    """This class allows low-level access to a stream of pseudo-random bytes"""

    def __init__(self, seed, hasher=skein512):
        """Initialize with bytes object 'seed'"""
        self._hasher = hasher
        self.state_size = hasher().block_size
        self._state = bytes(self.state_size)
        self._lock = threading.Lock()
        self.seed(seed)

    def seed(self, seed):
        """Reseed with bytes object 'seed'"""
        with self._lock:
            h = self._hasher(self._state + seed)
            self._state = h.digest()

    def read(self, n: int):
        """Return 'n' pseudo-random bytes"""
        with self._lock:
            h = self._hasher(self._state, digest_bits=8 * (self.state_size + n))
            self._state = h.digest(0, self.state_size)
            return h.digest(self.state_size, self.state_size + n)


###
### Stream Cipher ###
###


class StreamCipher:
    DIGEST_BITS = 2 ** 64 - 1

    def __init__(self, key: bytes, nonce: bytes = b"", hasher=skein512):
        self._h = hasher(key=key, nonce=nonce, digest_bits=self.DIGEST_BITS)
        self._pos = 0
        self._lock = threading.Lock()

    def keystream(self, n: int):
        """Return 'n' bytes from the keystream"""
        with self._lock:
            stream = self._h.digest(self._pos, self._pos + n)
            self._pos += n
        return stream

    def encrypt(self, plain):
        """Encrypt bytes-like object 'plain' with keystream"""
        if not isinstance(plain, (bytes, bytearray, memoryview)):
            raise TypeError("argument must be a bytes object")

        # Reserve the keystream slice atomically with the position advance so
        # concurrent encrypt() calls cannot reuse the same keystream bytes.
        with self._lock:
            stream = self._h.digest(self._pos, self._pos + len(plain))
            self._pos += len(plain)
        return bytes(x ^ y for x, y in zip(plain, stream))

    decrypt = encrypt
