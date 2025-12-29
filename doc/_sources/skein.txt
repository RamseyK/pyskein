Skein hash
==========

A new hash object is created by one of the following three functions:

.. function:: skein.skein256(init=b'', digest_bits=256, **params)
.. function:: skein.skein512(init=b'', digest_bits=512, **params)
.. function:: skein.skein1024(init=b'', digest_bits=1024, **params)

    These constructor functions return a corresponding hash object
    for Skein-256, Skein-512, or Skein-1024 (i.e. 256, 512, or 1024 bits
    internal state).  They optionally take an initial chunk of data to hash
    (`init`) and the desired digest length in bits (`digest_bits`,
    must be < 2**31).

    Further optional (keyword-only) parameters are:

        * `key`: private key, arbitrary bytes
        * `pers`: personalization string, arbitrary bytes
        * `public_key`: public key, arbitrary bytes
        * `key_id`: key identifier, arbitrary bytes
        * `nonce`: nonce value, arbitrary bytes
        * `tree`: tree hashing parameters, a tuple (leaf, fan_out, max_height)

    For details about the meaning of these parameters, please consult the
    `Skein specification`_.

.. _`Skein specification`: http://www.skein-hash.info/sites/default/files/skein1.3.pdf


Hash objects
------------

Hash objects have the following methods:

.. method:: hash.update(message, bits=None)

   Hash the given `message` (of type bytes) into the internal state.  (Strings
   have to be encoded to bytes first.) Repeated calls are equivalent
   to a single call with the concatenation of all the arguments.

   If given, the argument `bits` has to be ``<=8*len(message)`` and specifies
   how many bits of the message are hashed. Specifically, the first ``bits//8``
   full bytes and the ``bits%8`` most significant bits of the following byte
   are hashed. If omitted, `bits` defaults to ``8*len(message)``.

   *Caveat:* If the number of hashed bits so far is not a multiple of 8, then
   `bits` must be specified with a value of at most ``8-hashed_bits%8``.
   Otherwise a ``ValueError`` will be raised. This ensures proper byte
   alignment of subsequent hashing operations.

.. method:: hash.digest([start, stop])

   Return the digest of all data processed so far. Usually, `start` and `stop`
   are omitted, and this is a bytes object of length :attr:`digest_size`.

   If `start` and `stop` are specified, the result is the same as that of
   ``digest()[start:stop]``, but computed much more efficiently for small
   slices of large digests. This is useful, e.g., for turning Skein into a
   stream cipher.

.. method:: hash.hexdigest

   Like :meth:`digest`, but returning the digest as a string
   of hexadecimal digits.

.. method:: hash.copy

   Return a clone of the hash object, e.g. to efficiently compute hashes of
   data sharing a common prefix.


In addition each hash object has the following attributes:

.. attribute:: hash.name

   Name of the algorithm, i.e. ``'Skein-256'``, ``'Skein-512'``, or
   ``'Skein-1024'``.

.. attribute:: hash.block_bits

   Internal state size in bits, i.e. ``256``, ``512``, or ``1024``.

.. attribute:: hash.block_size

   Internal state size in bytes (conforming to :mod:`hashlib`),
   i.e. ``32``, ``64``, or ``128``.

.. attribute:: hash.digest_bits

   Output digest length in bits, i.e. the value given to the constructor
   function (or default).

.. attribute:: hash.digest_size

   Digest size in bytes (rounded up).

.. attribute:: hash.hashed_bits

   Number of message bits hashed so far.

*Note:* Hash objects are picklable, but the pickled data exposes a buffer
with up to one block of still unhashed data.


Examples of simple hashing
--------------------------

Make a Skein-512 hash object with default digest length (512 bits)
and hash some data::

    >>> from skein import skein256, skein512, skein1024
    >>> h = skein512()
    >>> h.update(b'Nobody inspects')
    >>> h.update(b' the spammish repetition')
    >>> h.digest()
    b'\x1bN\x03+\xcb\x1d\xa4Rs\x01\x1c\xa9Ee\xef\x10|f+\x0b\xd3\r[5\xfbS5Ko\xced#\xa5\xeb\x10\xda\xe6\xf3v\xd6\xb2JNQ}\x85\xc7&\xfc\x01\xfb\x87J\x8f\xe2m\xe9Y\x1f\xa5\x9f\xa3\xc7\xd4'
    >>> h.digest_size, h.digest_bits
    (64, 512)
    >>> h.block_size, h.block_bits
    (64, 512)
    >>> h.hashed_bits
    312

Similarly for Skein-1024-384::

    >>> h = skein1024(b'Nobody inspects the spammish repetition', digest_bits=384)
    >>> h.hexdigest()
    'b602b02c5e02ecb37361b17dd4da33bb41c49ff685dca0408048a425fe3dee8bfbaf6c42575e9d71d89eb0dd2ec2a2a8'
    >>> h.digest_size, h.digest_bits
    (48, 384)
    >>> h.block_size, h.block_bits
    (128, 1024)
    >>> h.hashed_bits
    312


Examples of input parameter usage
---------------------------------

To generate a message authentication code (MAC), use the `key` input::

    >>> skein256(b'message', key=b'secret').hexdigest()
    'aee7b931f0e5e134b7af4ac1a7958f5c5f5f7e20dd68cfeab474c0aae0290de7'

You may specify a personalization string for personalized hashing::

    >>> skein256(b'message', pers=b'20100101 me@example.com').hexdigest()
    '00c4f6aa109902e8db81d4c9324d2980265adcda583090aa894447511ca5f773'

Similarly, a nonce may be specified for randomized hashing::

    >>> skein256(b'message', nonce=b'foobar').hexdigest()
    'e01f8f8d57521f28d08390be94da96390177eff11932eaa59e2976686ac4a280'

For digital signatures, the public key may be hashed into the digest::

    >>> skein256(b'message', public_key=b'mypubkey').hexdigest()
    '81a3a49606da1acf1a1ab3324e7ca170f310d905f8fabcff096d4ddf12aeef10'

Finally, to use Skein as a key derivation function (KDF), you may specify the
master key as `key` and the key identifier as `key_id`::

    >>> skein256(key=b'mastersecret', key_id=b'email', digest_bits=128).hexdigest()
    'c3ad501b1abfcf25bd1bdc4ef4053348'

Tree hashing
------------

Tree hashing uses the same incremental interface as sequential hashing. To hash
with a leaf size of 2**L blocks, a fan-out of 2**F children per node and a
maximum tree height of M, simply specify a `tree` parameter of (L, F, M)::

    >>> h = skein256(tree=(5, 2, 255))
    >>> for _ in range(1000):
    ...     h.update(b'\0' * 10**6)
    ...
    >>> h.update(b'foobar')
    >>> h.hexdigest()
    '3d5bea7b8e2ffdaef60ce9d68b1db7cb4549a6bb52b3801eda640623cbeca5bd'

In tree hashing mode, PySkein will use two threads to speed up hashing on
multi-core systems. Note that the digests produced in tree hashing differ from
those produced in sequential hashing, and also depend on the `tree` parameter.
If you are not restricted by interoperability issues, you can try different
leaf sizes to find the value leading to optimal performance on your machine.
