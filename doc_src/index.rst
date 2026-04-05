PySkein - The Skein Hash Algorithm for Python
=============================================

PySkein is a C extension module for Python implementing the
`Skein hash algorithm`_, one of the five finalists of the
`NIST SHA-3 Competition`_. While ultimately not selected
as the winner of that competition, Skein remains a well-studied
design offering unique capabilities not found in SHA-3 or SHA-2.

PySkein provides all features of Skein through a Pythonic interface
and is released as free software under the `GNU General Public License`_.


How Skein works
---------------

Skein is built on top of **Threefish**, a tweakable block cipher that
uses only 64-bit addition, rotation, and XOR (the "ARX" design).
Threefish comes in three variants — Threefish-256, -512, and -1024 —
named after their internal state size in bits.

Skein uses Threefish through a construction called **UBI** (Unique
Block Iteration).  Each UBI call processes one type of input (message,
key, configuration, etc.) and produces a fixed-size chaining value that
becomes the key for the next UBI call.  A 128-bit *tweak* distinguishes
calls from each other, preventing inputs of one type from being
substituted for another.

The full hashing pipeline is::

    IV (all zeros)
      ↓ UBI[key]          optional, enables MAC / KDF
      ↓ UBI[config]       always present (digest length, tree params, …)
      ↓ UBI[pers]         optional personalization string
      ↓ UBI[public_key]   optional
      ↓ UBI[key_id]       optional
      ↓ UBI[nonce]        optional
      ↓ UBI[message]      the data being hashed
      ↓ UBI[out, ctr=0]   counter-mode output: produces first block of digest
      ↓ UBI[out, ctr=1]   …and so on for as many output bits as requested

Because each component is hashed with a distinct type tag, all
combinations of optional parameters produce unrelated digests without
any risk of collision across parameter types.


Highlights
----------

* **Simple interface** following the hash API of Python's standard library
  (like :mod:`hashlib`), making Skein a drop-in alternative.

* **All features** of the Skein specification: flexible digest sizes,
  MAC generation, personalized hashing, tree hashing, and more.

* **Extendable output** — ``digest_bits`` can be any value from 1 to
  2\ :sup:`64`\-1, turning Skein into an XOF (extendable output function)
  for use as a key derivation function or stream cipher.

* **High performance** through an optimized C implementation of Threefish.

* **Threefish** available standalone for direct encryption and decryption.

* **PRNG and stream cipher** implementations built on Skein.

* **Free-threaded Python** (PEP 703) supported: all objects are protected
  by per-object locks so they can be safely shared between threads.

.. _`GNU General Public License`: http://www.gnu.org/licenses/gpl-3.0.html
.. _`Skein hash algorithm`: https://en.wikipedia.org/wiki/Skein_(hash_function)
.. _`NIST SHA-3 Competition`: http://csrc.nist.gov/groups/ST/hash/sha-3/index.html


Table of Contents:

.. toctree::
    :maxdepth: 2

    skein
    threefish
    random
    stream
    scripts
    download
