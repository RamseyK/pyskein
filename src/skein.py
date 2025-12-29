# skein.py
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

__version__ = "1.0"

from _skein import skein256, skein512, skein1024, threefish


###
### Skein-PRNG ###
###

import random

class Random(random.Random):
    _BPF = random.BPF
    _RECIP_BPF = random.RECIP_BPF
    _TWEAK = bytes(15) + b"\x3f"
    _random = random

    def __init__(self, seed=None, hasher=skein512):
        """Initialize SkeinRandom instance.

        - 'seed' as in method seed().
        - 'hasher' may be skein256, skein512, or skein1024.
        """
        self._hasher = hasher
        self._state_bytes = hasher().block_size
        self._state = bytes(self._state_bytes)
        self._counter0 = bytes(self._state_bytes)
        self._counter1 = b"\1" + bytes(self._state_bytes-1)
        super().__init__(seed)


    def seed(self, seed=None):
        """Initialize internal state from hashable object.

        If seed is a bytes object, set state according to Skein specification.
        Otherwise derive a bytes object from the seed using random.Random.
        """
        if not isinstance(seed, bytes):
            r = self._random.Random(seed)
            seed = bytes(r.randrange(256) for _ in range(self._state_bytes))
        self._state = self._hasher(self._state+seed).digest()
        self._buffer = b""
        self._number = 0
        self._bits = 0


    def read(self, n):
        """Return n random bytes.

        The stream of random bytes is reproducible for a given seed:

        >>> r = Random(seed)
        >>> assert r.read(m)+r.read(n) == Random(seed).read(m+n)
        """
        if n < 0:
            raise ValueError("number of random bytes needs to be >= 0")
        if len(self._buffer) < n:
            chunks = [self._buffer]
            blocks = ((n-len(self._buffer)-1) // self._state_bytes) + 1
            for i in range(1, blocks+1):
                output = threefish(self._state, self._TWEAK).encrypt_block
                self._state = output(self._counter0)
                chunks.append(output(self._counter1))
            self._buffer = b"".join(chunks)
            assert len(self._buffer) >= n
        res, self._buffer = self._buffer[:n], self._buffer[n:]
        return res


    def getrandbits(self, k):
        """Return an int with k random bits"""
        bits = self._bits
        for b in self.read((k-self._bits-1)//8+1):
            self._number |= b << bits
            bits += 8
        r = self._number & ((1<<k)-1)
        self._number >>= k
        self._bits = bits - k
        return r


    def random(self):
        """Get the next random number in the range [0.0, 1.0)"""
        return self.getrandbits(self._BPF) * self._RECIP_BPF


    def getstate(self):
        """Return internal state; can be passed to setstate() later."""
        return (self._state,
                self._buffer, self._number, self._bits,
                self.gauss_next)


    def setstate(self, state):
        """Restore internal state from object returned by getstate()."""
        (self._state,
            self._buffer, self._number, self._bits,
            self.gauss_next) = state

del random


class RandomBytes:
    """This class allows low-level access to a stream of pseudo-random bytes"""

    def __init__(self, seed, hasher=skein512):
        """Initialize with bytes object 'seed'"""
        self._hasher = hasher
        self.state_size = hasher().block_size
        self._state = bytes(self.state_size)
        self.seed(seed)

    def seed(self, seed):
        """Reseed with bytes object 'seed'"""
        h = self._hasher(self._state+seed)
        self._state = h.digest()

    def read(self, n):
        """Return 'n' pseudo-random bytes"""
        h = self._hasher(self._state, digest_bits=8*(self.state_size+n))
        self._state = h.digest(0, self.state_size)
        return h.digest(self.state_size, self.state_size+n)


###
### Stream Cipher ###
###

class StreamCipher:
    DIGEST_BITS = 2**64-1

    def __init__(self, key, nonce=b"", hasher=skein512):
        self._h = hasher(key=key, nonce=nonce, digest_bits=self.DIGEST_BITS)
        self._pos = 0

    def keystream(self, n):
        """Return 'n' bytes from the keystream"""
        newpos = self._pos + n
        stream = self._h.digest(self._pos, newpos)
        self._pos = newpos
        return stream

    def encrypt(self, plain):
        """Encrypt bytes object 'plain' with keystream"""
        stream = self.keystream(len(plain))
        try:
            return bytes(x^y for x, y in zip(plain, stream))
        except TypeError as e:
            self._pos -= len(plain)
            raise TypeError("argument must be a bytes object") from e

    decrypt = encrypt
