PySkein 1.0 - The Skein Hash Algorithm for Python
=================================================

PySkein is an extension module for Python, implementing the
`Skein hash algorithm`_, one of the five finalists of the
`NIST SHA-3 Competition`_. While ultimately not selected
as the winner of that competition, Skein may still be
useful as an alternative hash algorithm, offering flexible
hashing modes with various parameters. PySkein provides all
features of Skein through a Pythonic interface and is released
as free software under the `GNU General Public License`_.
Its highlights are:

* **Simple interface** following the hash algorithms in the
  Python standard library (like `hashlib.sha1` or
  `hashlib.sha256`)

* **All features** of the Skein specification
  (flexible digest sizes, MAC generation, tree hashing, and
  various others)

* **High performance** through optimized C implementation
  (7.1 cycles/byte for sequential hashing and 4.2 cycles/byte
  for tree hashing on two cores, measured on an Athlon 64 X2)

* **Threefish**, the tweakable block cipher used in Skein,
  available for encryption and decryption on its own

.. _`GNU General Public License`: http://www.gnu.org/licenses/gpl-3.0.html
.. _`Skein hash algorithm`: http://www.skein-hash.info
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
