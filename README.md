# PySkein

PySkein is a Python native extension implementation the [Skein hash algorithm](https://en.wikipedia.org/wiki/Skein_(hash_function)). Skein was one of the five finalists of the
NIST SHA-3 Competition. While ultimately not selected as the winner of that competition, Skein may still be useful as an
alternative hash algorithm, offering flexible hashing modes with various parameters. PySkein provides all features of
Skein through a Pythonic interface and is released as free software under the `GNU General Public License`.

Its highlights are:

* **Simple interface** following the hash algorithms in the Python standard library (like `hashlib.sha1` or
  `hashlib.sha256`)

* **All features** of the Skein specification (flexible digest sizes, MAC generation, tree hashing, and various others)

* **High performance** through optimized C implementation

* **Threefish**, the tweakable block cipher used in Skein, available for encryption and decryption on its own

## Installation

* Install with Python 3.11 or higher: `python -m pip install pyskein`

## Usage

* Call from your program like so

```bash
>> import skein
>> h = skein.skein256()
>> h.update(b"hello")
>> h.hexdigest()
'8b467f67dd324c9c9fe9aff562ee0e3746d88abcb2879e4e1b4fbd06a5061f89'
```

* Or, use included console scripts `skeinsum` or `threefish`

## Caveats

* Earlier versions of PySkein may implement different versions of the Skein algorithm and so produce different hash
  outputs. Check doc/download.html for an overview of which version of PySkein corresponds to which version of the Skein
  specification.

# Copyright and License Information

Copyright 2008-2013 Hagen Fürstenau. Further updates by Ramsey Kant.
Both the software and the documentation are licensed under GPL version 3.
For the license text see the file "COPYING".
