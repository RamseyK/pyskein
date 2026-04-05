Demo Scripts
============

Three Python scripts are included in the distribution to demonstrate
PySkein's capabilities.  They are installed into the system ``PATH`` so
you can run them directly from the command line.

.. note::
   These scripts are written to demonstrate PySkein functionality.
   They are not audited for production security use.


skeinsum
--------

Computes Skein-512-256 digests of files, mimicking the behaviour of the
Unix tools ``md5sum``, ``sha1sum``, and ``sha256sum``.

Usage::

    $ skeinsum [file ...]

With no arguments, ``skeinsum`` reads from standard input::

    $ echo -n "hello" | skeinsum
    3a1b0a3e...  -

With one or more file arguments, each file is hashed in turn::

    $ skeinsum COPYING LICENSE
    63fb45390c188b7ba0e8eb2ed0e2fefa8416da515f0b28e670345ecd0de673dc  COPYING
    ...  LICENSE

The format of each output line is ``<hexdigest>  <filename>``, compatible
with the ``--check`` mode of the ``sha*sum`` tools (with an appropriate
``-a`` flag on BSD versions).

The digest algorithm is ``skein512(digest_bits=256)``: Skein-512 internal
state with a 256-bit (32-byte) output, giving a 64-character hex string.


threefish
---------

Encrypts and decrypts files using Threefish-256 in a variant of
**tweak block chaining** (TBC) mode.  This mode is designed specifically
for tweakable block ciphers: the first 16 bytes of each ciphertext block
become the tweak for the next block, chaining blocks together in a way
that is analogous to CBC but exploits the tweak input rather than XOR.

Usage::

    $ threefish encrypt <file>   # produces <file>.3f
    $ threefish decrypt <file>.3f  # restores <file>

The 256-bit encryption key is derived from a password entered at the
prompt by computing ``skein512(password, digest_bits=256)``.

File format of the encrypted output:

* **16 bytes** — random initial tweak, written at the start of the file.
* **Full blocks** — each 32-byte block is encrypted, and its first 16
  bytes become the tweak for the next block.
* **Final block** — padded to 32 bytes with random bytes; the 5 least
  significant bits of the last byte encode the number of original bytes in
  the final block (0–31), allowing exact recovery of the original length.

Example session::

    $ threefish encrypt README
    Password:
    $ ls README*
    README  README.3f
    $ mv README README.orig
    $ threefish decrypt README.3f
    Password:
    $ diff README README.orig
    $

.. note::
   Decryption always succeeds without reporting whether the key is correct;
   a wrong key produces garbage output silently.  Add a checksum or
   authenticated encryption wrapper if integrity verification is needed.


skein-random
------------

Writes an unlimited stream of cryptographically seeded pseudo-random bytes
to standard output.  It seeds :class:`skein.RandomBytes` from
``/dev/random`` and periodically mixes in additional entropy.

Usage::

    $ skein-random          # silent; pipe to a consumer
    $ skein-random -v       # verbose: prints seeding progress to stderr

The initial seeding reads exactly ``state_size`` bytes (64 bytes for the
default Skein-512) from ``/dev/random``, waiting until enough entropy is
available.  After each 1 MiB chunk of output, ``/dev/random`` is polled
again (non-blocking) and any available bytes are mixed into the state
with :meth:`~skein.RandomBytes.seed`, strengthening the output stream
against state-compromise attacks.

Example — generate a 256-byte random key and encode it as hex::

    $ skein-random | head -c 32 | xxd -p
    a3f6...

Example — use as a source for ``dd`` (e.g. to benchmark)::

    $ skein-random | dd of=/dev/null bs=1M count=100
