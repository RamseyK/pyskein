Pseudorandom Number Generator
=============================

PySkein provides two PRNG classes.  Both are deterministic given the same
seed and are designed according to the Skein specification's recommendations
for pseudorandom generation.


:class:`skein.Random`
---------------------

A drop-in replacement for :class:`random.Random` from the standard library,
backed by Threefish in counter mode.

.. class:: skein.Random(seed=None, hasher=skein512)

    Create a new :class:`Random` instance.

    ``seed`` initialises the internal state.  If ``seed`` is a
    :class:`bytes` object it is mixed directly into the state using Skein.
    Any other value (integer, string, …) is first passed through
    :class:`random.Random` to derive a bytes seed of the appropriate length,
    matching the behaviour of the standard library's :class:`random.Random`.
    If ``seed`` is ``None``, a suitable source of system randomness is used
    (``/dev/urandom`` or equivalent).

    ``hasher`` selects the Skein variant: ``skein256``, ``skein512`` (the
    default), or ``skein1024``.  The internal state size equals the hasher's
    block size (32, 64, or 128 bytes respectively).

    Because each ``seed()`` call *mixes* the new seed into the existing
    state rather than replacing it, repeated seeding accumulates entropy
    without resetting the PRNG to a known point.

The internal construction runs Threefish (keyed by the current state) in
counter mode using the Skein output-type tweak.  Encrypting counter value 0
advances the state; encrypting counter value 1 produces output bytes.  This
two-block scheme keeps state advancement and output derivation independent,
so an attacker who observes the output stream cannot recover the internal
state.

Usage::

    >>> import skein
    >>> r = skein.Random(b"some seed value")
    >>> r.random()
    0.12674259115116804

Any hashable object can be used as a seed::

    >>> skein.Random(12345).random()
    0.1976938882004089

When no seed is given, the initial state comes from a system randomness
source::

    >>> r = skein.Random()
    >>> r.random()
    0.9696830103216001  # different each time

Additional methods beyond the standard :class:`random.Random` interface:

.. method:: Random.read(n)

    Return ``n`` pseudo-random bytes as a bytes object.  The stream is
    reproducible: for a given seed, ``r.read(m) + r.read(n)`` always equals
    ``Random(seed).read(m + n)``::

        >>> r = skein.Random(b"seed")
        >>> r.read(5)
        b'\xfe\xe6j\x8d\xb6'
        >>> r.getrandbits(4)
        9

.. method:: Random.getrandbits(k)

    Return a non-negative integer with ``k`` random bits.

.. method:: Random.getstate()

    Return a snapshot of the internal state (a tuple).  Can be passed to
    :meth:`setstate` to restore the PRNG to this exact point.

.. method:: Random.setstate(state)

    Restore the internal state from a snapshot returned by :meth:`getstate`.

All other methods (``random()``, ``randint()``, ``choice()``, etc.) are
inherited from :class:`random.Random` and documented in the
`Python standard library documentation`_.

.. _`Python standard library documentation`: https://docs.python.org/3/library/random.html


:class:`skein.RandomBytes`
--------------------------

A lower-level PRNG that exposes only the raw byte stream.  It uses a
simpler construction than :class:`Random` — Skein itself (rather than
bare Threefish) is called at each step — which makes it better suited to
cases where you need large amounts of pseudo-random bytes derived from a
bytes seed, with periodic re-seeding from external entropy.

.. class:: skein.RandomBytes(seed, hasher=skein512)

    Create a new :class:`RandomBytes` instance.

    ``seed`` must be a :class:`bytes` object.

    ``hasher`` selects the Skein variant, defaulting to ``skein512``.

    The internal state is initialised to all zeros and then immediately
    mixed with ``seed``.

.. method:: RandomBytes.seed(seed)

    Mix additional bytes into the current state.  Can be called at any time
    to add new entropy without restarting the sequence::

        rb.seed(os.urandom(64))  # periodically add OS entropy

.. method:: RandomBytes.read(n)

    Return ``n`` pseudo-random bytes.  The internal state advances with
    each call, so subsequent calls yield different bytes::

        >>> from skein import RandomBytes
        >>> rb = RandomBytes(b"my seed")
        >>> rb.read(8)
        b'...'
        >>> rb.read(8)  # different bytes
        b'...'

.. attribute:: RandomBytes.state_size

    The internal state size in bytes (32, 64, or 128, depending on the
    hasher).
