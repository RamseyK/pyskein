Skein hash
==========

A new hash object is created by one of the following three functions:

.. function:: skein.skein256(init=b'', digest_bits=256, **params)
.. function:: skein.skein512(init=b'', digest_bits=512, **params)
.. function:: skein.skein1024(init=b'', digest_bits=1024, **params)

    These constructor functions return a hash object for Skein-256, Skein-512,
    or Skein-1024, named after their internal state size in bits.

    ``init`` is an optional initial chunk of data to hash immediately.

    ``digest_bits`` sets the output length in bits.  It may be any integer
    from 1 to 2\ :sup:`64`\-1, making Skein an extendable output function
    (XOF): you can request any number of output bits without changing the
    security of the construction.  Defaults to the state size (256, 512, or
    1024).

    All remaining parameters are keyword-only and correspond to the optional
    UBI input types defined in the Skein specification (§2.1).  Each type is
    processed through a separate UBI (Unique Block Iteration) call before the
    message is hashed, so all combinations produce independent digests:

    ``key`` *(bytes)*
        A secret key.  Hashing with a key produces a message authentication
        code (MAC); omitting the key gives a plain hash.  The same data with
        different keys always produces unrelated digests.

    ``pers`` *(bytes)*
        A personalization string.  Use this to bind a hash to a specific
        application or context (e.g. ``b'MyApp v2 login tokens'``), ensuring
        that hashes from one application cannot be confused with those from
        another, even if the message data is identical.

    ``public_key`` *(bytes)*
        A public key value, for use in signature schemes that hash the message
        together with the signer's public key.

    ``key_id`` *(bytes)*
        A key identifier, used together with ``key`` to implement key
        derivation functions (KDF): the same master key with different
        ``key_id`` values produces independent derived keys.

    ``nonce`` *(bytes)*
        A nonce value for randomized hashing.  Hashing the same message with
        different nonces produces independent digests, which can prevent
        multi-target attacks.

    ``tree`` *(tuple)*
        Tree hashing parameters ``(leaf, fan_out, max_height)``.  See
        `Tree hashing`_ below.

    For authoritative definitions of each parameter, see the
    `Skein specification`_.

.. _`Skein specification`: http://www.skein-hash.info/sites/default/files/skein1.3.pdf


Hash objects
------------

Hash objects have the following methods:

.. method:: hash.update(message, bits=None)

   Feed ``message`` (bytes) into the hash state.  Repeated calls are
   equivalent to a single call with the concatenation of all arguments::

       h.update(a); h.update(b)  ==  h.update(a + b)

   ``bits``, if given, must satisfy ``0 <= bits <= 8*len(message)`` and
   specifies exactly how many bits of ``message`` are consumed.  The first
   ``bits // 8`` complete bytes and the ``bits % 8`` most-significant bits of
   the following byte are hashed.  When omitted, ``bits`` defaults to
   ``8 * len(message)`` (all bytes).

   *Partial-byte alignment:* if the total number of bits hashed so far is not
   a multiple of 8, the next ``update()`` call must use ``bits`` with a value
   of at most ``8 - (hashed_bits % 8)``.  Providing more bits, or omitting
   ``bits`` when alignment is incomplete, raises ``ValueError``.  This
   restriction exists because Skein processes data in whole bytes internally;
   partial bytes are padded and marked with a special tweak flag so the
   padding can always be unambiguously removed.

.. method:: hash.digest([start, stop])

   Return the digest of all data hashed so far as a bytes object.

   When called without arguments, returns ``digest_size`` bytes (the full
   digest).

   When called with ``start`` and ``stop``, returns only bytes
   ``[start:stop]`` of the full digest, equivalent to
   ``digest()[start:stop]`` but computed much more efficiently.  This is
   because Skein's output stage runs Threefish in counter mode: each output
   block is independent, so only the blocks covering ``[start, stop)`` need
   to be computed.  This makes sliced output practical even for very large
   digests.

   Calling ``digest()`` does not advance or modify the hash state, so it can
   be called multiple times with consistent results.

.. method:: hash.hexdigest()

   Like :meth:`digest`, but returns the digest as a lowercase hexadecimal
   string.

.. method:: hash.copy()

   Return a deep copy of the hash object.  Use this to efficiently compute
   hashes of data sharing a common initial prefix: hash the shared prefix
   into one object, copy it, then feed different suffixes into each copy.


Hash object attributes
----------------------

.. attribute:: hash.name

   Name string identifying the variant: ``'Skein-256'``, ``'Skein-512'``,
   or ``'Skein-1024'``.

.. attribute:: hash.block_bits

   Internal state size in bits: ``256``, ``512``, or ``1024``.  This is the
   size of the Threefish key and block used internally, not the output size.

.. attribute:: hash.block_size

   Internal state size in bytes: ``32``, ``64``, or ``128``.  Provided for
   compatibility with :mod:`hashlib`.

.. attribute:: hash.digest_bits

   Output length in bits, as given to the constructor.  May differ from
   ``block_bits``.

.. attribute:: hash.digest_size

   Output length in bytes, rounded up from ``digest_bits``.

.. attribute:: hash.hashed_bits

   Number of message bits consumed so far.  When partial-byte input has been
   used, this may not be a multiple of 8.

*Note:* Hash objects support pickling (``pickle.dumps`` / ``pickle.loads``).
The pickled form includes up to one block of buffered but not yet processed
data, so treat pickled hash objects with the same confidentiality as the data
being hashed.


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

Requesting a smaller digest than the state size (Skein-1024 with 384-bit
output)::

    >>> h = skein1024(b'Nobody inspects the spammish repetition', digest_bits=384)
    >>> h.hexdigest()
    'b602b02c5e02ecb37361b17dd4da33bb41c49ff685dca0408048a425fe3dee8bfbaf6c42575e9d71d89eb0dd2ec2a2a8'
    >>> h.digest_size, h.digest_bits
    (48, 384)
    >>> h.block_size, h.block_bits
    (128, 1024)

You can also request *more* bits than the state size.  The additional bits
are generated by running extra counter-mode output blocks::

    >>> len(skein256(b'hello', digest_bits=1024).digest())
    128


Examples of optional parameter usage
-------------------------------------

**MAC (message authentication code)** — use ``key`` to bind the digest to
a secret.  The output is indistinguishable from a random function of the
message to anyone who does not know the key::

    >>> skein256(b'message', key=b'secret').hexdigest()
    'aee7b931f0e5e134b7af4ac1a7958f5c5f5f7e20dd68cfeab474c0aae0290de7'

**Personalized hashing** — use ``pers`` to make a hash function specific to
one application, so that hashes produced by different applications (or
different versions) never collide even for identical inputs::

    >>> skein256(b'message', pers=b'20100101 me@example.com').hexdigest()
    '00c4f6aa109902e8db81d4c9324d2980265adcda583090aa894447511ca5f773'

**Randomized hashing** — use ``nonce`` to produce a different digest for
each call, protecting against multi-target preimage attacks::

    >>> skein256(b'message', nonce=b'foobar').hexdigest()
    'e01f8f8d57521f28d08390be94da96390177eff11932eaa59e2976686ac4a280'

**Signature hashing** — embed the signer's public key so the digest is
bound to a specific key pair::

    >>> skein256(b'message', public_key=b'mypubkey').hexdigest()
    '81a3a49606da1acf1a1ab3324e7ca170f310d905f8fabcff096d4ddf12aeef10'

**Key derivation (KDF)** — use ``key`` as the master secret and ``key_id``
to derive independent sub-keys for different purposes::

    >>> skein256(key=b'mastersecret', key_id=b'email', digest_bits=128).hexdigest()
    'c3ad501b1abfcf25bd1bdc4ef4053348'
    >>> skein256(key=b'mastersecret', key_id=b'session', digest_bits=128).hexdigest()
    '...'  # different key for a different purpose

**Sliced output** — efficiently compute a substring of a large digest.
Useful when using Skein as a stream cipher or KDF with many output bytes::

    >>> h = skein512(b'data', digest_bits=10000)
    >>> h.digest(100, 200)  # only bytes 100-199, without computing the rest
    b'...'


Tree hashing
------------

Tree hashing splits the message across multiple parallel hash chains that
are combined in a binary tree, enabling multi-core acceleration.

The ``tree`` parameter is a tuple ``(leaf, fan_out, max_height)`` where:

* ``leaf`` — each leaf node processes at most 2\ :sup:`leaf` blocks of input
  (a block is ``block_size`` bytes).  Larger values mean less overhead per
  leaf but longer serial sections.

* ``fan_out`` — each internal tree node combines 2\ :sup:`fan_out` child
  node outputs.  Fan-out of 1 (2 children) is typical for two-core machines.

* ``max_height`` — maximum number of tree levels, at least 2.  255 means
  an unlimited-height tree and is the safe default for variable-length input.

Tree hashing uses the same incremental API as sequential hashing::

    >>> h = skein256(tree=(5, 2, 255))
    >>> for _ in range(1000):
    ...     h.update(b'\0' * 10**6)
    ...
    >>> h.update(b'foobar')
    >>> h.hexdigest()
    '3d5bea7b8e2ffdaef60ce9d68b1db7cb4549a6bb52b3801eda640623cbeca5bd'

PySkein uses two threads internally to parallelize leaf hashing on
multi-core systems.

.. note::
   Tree hashing produces different digests than sequential hashing, and the
   digest also depends on all three tree parameters.  Always record and fix
   the ``tree`` tuple if interoperability is required.
