Pseudorandom Number Generator
=============================

PySkein contains a PRNG designed according to the Skein specification and based
on Skein-512 by default. It is implemented in Python as a subclass of the
standard library's :class:`random.Random` class and can therefore be used in
the same way. The seed may be given as a :class:`bytes` object::

    >>> import skein
    >>> r = skein.Random(b"some seed value")
    >>> r.random()
    0.12674259115116804

or any other hashable object - in which case :class:`random.Random` is used
internally to derive a :class:`bytes` seed::

    >>> skein.Random(12345).random()
    0.1976938882004089

The same happens when no seed is given, so that the initial state is then
derived from a suitable system source of randomness (like /dev/urandom or the
time)::

    >>> r = skein.Random()
    >>> r.random()
    0.9696830103216001

You may also directly read bytes or bits from the random stream::

    >>> r = skein.Random(b"seed")
    >>> r.read(5)
    b'\xfe\xe6j\x8d\xb6'
    >>> r.getrandbits(4)
    9

All other methods of :class:`skein.Random` are based on :meth:`random()`.
For their documentation please refer to the `Python documentation`_.

.. _`Python documentation`: http://docs.python.org/py3k/
