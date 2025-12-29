Download PySkein
================

PySkein runs with Python 3.1 or higher. It was mainly tested on 64-bit Linux,
but should run on various platforms supported by Python. Due to the design of
the Skein algorithm, performance is significantly lower on 32-bit systems.

Download the most recent version 1.0:

    * **Source code:** `pyskein-1.0.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-1.0.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-1.0.tar.gz.asc>`__)

    * **Windows installer (for Python 3.3):** `pyskein-1.0.win32-py3.3.msi <http://pypi.python.org/packages/3.3/p/pyskein/pyskein-1.0.win32-py3.3.msi>`_ (`sig <http://pypi.python.org/packages/3.3/p/pyskein/pyskein-1.0.win32-py3.3.msi.asc>`__)

Note: If you have a version of PySkein <0.5 installed, please make sure to
manually delete "skein.*" from your Python `site-packages` directory before
installing a more recent version.


Skein versions
--------------

Older versions of PySkein may implement previous versions of the Skein
specification and therefore produce different hashing outputs.  The following
table shows which version of PySkein corresponds to which version of the
specification:

===========  =======================  ==============================
**PySkein**  **Skein specification**  **Change**
===========  =======================  ==============================
since 0.7    1.3                      new key schedule constant
0.5 - 0.6.3  1.2                      new rotation constants
0.1 - 0.4    1.1                      corrected config string length
===========  =======================  ==============================

Version 1.0 of the Skein specification contained an `error
<http://www.schneier.com/blog/archives/2008/10/the_skein_hash.html#c323538>`_
in the reference implementation and test vectors, and was never implemented in
any release of PySkein.

Changes between version
-----------------------

1.0
    - Removed deprecated alias 'mac' for parameter 'key'

    - Added method Random.getrandbits, enabling arbitrarily large
      random number in Random.randrange  (proposed by Aaron Gallagher)

    - Dropped support for Python 3.0

0.7.1
    - Fixed a bug in digest(a, b), i.e. the optimization of digest()[a:b],
      where the last byte could be wrong when digest_size was large. This also
      affected the last byte of the output of StreamCipher.encrypt()!

    - Added RandomBytes class as a low-level PRNG interface

    - Added script 'skein-random', an efficient alternative to /dev/urandom

    - Fixed small bug where StreamCipher.encrypt() would advance the key stream
      even when raising an exception

    - Added method StreamCipher.keystream()  (proposed by Roy Kipp)

    - Allowed start == stop in digest(start, stop). As a consequence,
      StreamCipher.encrypt() now doesn't complain about empty byte objects.

0.7
    - Update to Skein Version 1.3 (tweak of key schedule constant)

    - Added the last two missing input parameters: 'public_key' and 'key_id'

    - Renamed 'mac' parameter to 'key', kept 'mac' as deprecated alias

    - Made keyword-only usage in skein*() mandatory

    - Extended digest() so that it can return slices of the digest

    - Increased digest_bits limit to 2**64-1 according to specification

    - Added StreamCipher

    - Revised PRNG to follow the specification more closely

0.6.3
    - Fixed tests to work with Python 3.2

    - Sped up generation of long digests

    - Allowed digest sizes of any number of bits (not only complete bytes)

    - Allowed message sizes of any number of bits (not only complete bytes)
      by introducing keyword argument 'bits' in update().

    - Added attribute "hashed_bits" to skein objects

0.6.2
    - Implemented second thread in tree hashing, using two cores on multi-core
      machines. This can improve hashing performance by more than 50%.

    - Included files to make re-building the docs work again

0.6.1
    - Fixed a bug in copy()ing tree hash objects

    - Made hash objects picklable

    - Improved repr() of hash objects

    - Fixed several issues with Python 3.0

0.6
    - Incremental tree hashing with arbitrary tree parameters

    - Restricted digest_bits to < 2^31 bits (256 MB!)

    - Disabled precomputed IVs (their performance benefit is negligible)

    - Deprecated all non-keyword arguments of skein*() functions
      except 'init' and 'digest_bits'

0.5.2
    - Release the GIL to allow multiple threads to hash in parallel
      on multi-core systems

0.5.1
    - Fixed reference leak when changing tweak value on threefish object

0.5
    - Updated rotation constants to new Skein specification (version 1.2)

    - Added implementation of Skein PRNG

0.4
    - Hashing with personalization string

    - Hashing with nonce value

0.3.1
    - Improved demo script "threefish"

    - Better compatibility with Python 3.1

0.3
    - Threefish block decryption

    - Demo scripts "skeinsum" and "threefish"

0.2
    - Support for message authentication codes

    - Threefish block encryption (but no decryption)

    - Fixed one or two reference leaks

0.1
    - Skein-256, Skein-512, and Skein-1024 hashing


Previous versions
-----------------

* `pyskein-0.7.1.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.7.1.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.7.1.tar.gz.asc>`__)

* `pyskein-0.7.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.7.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.7.tar.gz.asc>`__)

* `pyskein-0.6.3.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.6.3.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.6.3.tar.gz.asc>`__)

* `pyskein-0.6.2.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.6.2.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.6.2.tar.gz.asc>`__)

* `pyskein-0.6.1.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.6.1.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.6.1.tar.gz.asc>`__)

* `pyskein-0.6.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.6.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.6.tar.gz.asc>`__)

* `pyskein-0.5.2.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.5.2.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.5.2.tar.gz.asc>`__)

* `pyskein-0.5.1.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.5.1.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.5.1.tar.gz.asc>`__)

* `pyskein-0.5.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.5.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.5.tar.gz.asc>`__)

* `pyskein-0.4.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.4.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.4.tar.gz.asc>`__)

* `pyskein-0.3.1.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.3.1.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.3.1.tar.gz.asc>`__)

* `pyskein-0.3.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.3.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.3.tar.gz.asc>`__)

* `pyskein-0.2.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.2.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.2.tar.gz.asc>`__)

* `pyskein-0.1.tar.gz <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.1.tar.gz>`_ (`sig <http://pypi.python.org/packages/source/p/pyskein/pyskein-0.1.tar.gz.asc>`__)
