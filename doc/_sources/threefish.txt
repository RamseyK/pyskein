Threefish block cipher
======================

Threefish is the tweakable block cipher at the core of Skein.  Its design
uses only 64-bit addition, left rotation, and XOR (the "ARX" construction),
with no lookup tables or S-boxes, making it efficient and cache-timing-safe
on modern 64-bit hardware.

Threefish has three variants, named after their block (and key) size:

===============  ==========  ========
Variant          Block size  Rounds
===============  ==========  ========
Threefish-256    32 bytes    72
Threefish-512    64 bytes    72
Threefish-1024   128 bytes   80
===============  ==========  ========

The **tweak** is a 16-byte value that parameterises the cipher without
changing the key.  Encrypting the same plaintext with the same key but
different tweaks produces completely independent ciphertexts.  Skein uses
the tweak internally to carry a byte-position counter and type flags;
the standalone Threefish object exposes the tweak so you can implement
custom modes of operation.

.. function:: skein.threefish(key, tweak)

    Return a new Threefish cipher object.

    ``key`` must be a bytes object of length 32, 64, or 128, selecting
    Threefish-256, -512, or -1024 respectively.

    ``tweak`` must be exactly 16 bytes.  It is incorporated into every
    encryption and decryption operation, so changing the tweak produces an
    entirely different mapping from plaintext to ciphertext.


Threefish objects
-----------------

.. method:: threefish.encrypt_block(data)

    Encrypt a single block and return the ciphertext as a bytes object.

    ``data`` must be a bytes object of the same length as the key
    (32, 64, or 128 bytes).

.. method:: threefish.decrypt_block(data)

    Decrypt a single block and return the plaintext as a bytes object.

    ``data`` must be a bytes object of the same length as the key.

.. attribute:: threefish.tweak

    The current 16-byte tweak value.  This attribute is readable and
    writable.  Updating the tweak in place (rather than creating a new
    cipher object) is efficient and allows stateful modes such as cipher
    block chaining (CBC) to update the tweak after each block without
    re-deriving the full key schedule.

.. attribute:: threefish.block_bits

    Block size in bits: ``256``, ``512``, or ``1024``.

.. attribute:: threefish.block_size

    Block size in bytes: ``32``, ``64``, or ``128``.


Examples
--------

Basic encryption and decryption::

    >>> from skein import threefish
    >>> t = threefish(b'key of 32,64 or 128 bytes length', b'tweak: 16 bytes ')
    >>> t.block_size, t.block_bits
    (32, 256)
    >>> c = t.encrypt_block(b'block of data,same length as key')
    >>> c
    b'\x1c\xbf\x83\xbeoW\xd8\xe0f\xba\xb2\xea\x0e\x91\x0b\n\x06,\xd5:\x97\x9a\x11IaEGM\xc0\xe8\x9e\x86'
    >>> t.decrypt_block(c)
    b'block of data,same length as key'

Changing the tweak produces an independent ciphertext from the same key and
plaintext — demonstrating tweakable-cipher domain separation::

    >>> t.tweak = b'some other tweak'
    >>> c2 = t.encrypt_block(b'block of data,same length as key')
    >>> c2
    b'\xae\xc5\x8b\tX\x9c\x82\xfb\xa5m\x96\x87k|\x9fj\x136&P\xdb\x8af\x103t\x17]\xe5N\x01\xae'
    >>> t.decrypt_block(c2)
    b'block of data,same length as key'

Tweak block chaining (TBC) — a mode designed for tweakable ciphers where
the first 16 bytes of each ciphertext block become the tweak for the next.
This avoids the all-or-nothing feedback of CBC while still chaining blocks::

    >>> key = b'k' * 32
    >>> t = threefish(key, b'\x00' * 16)   # random initial tweak in practice
    >>> pt1 = b'first block: 32 bytes of data!!!'
    >>> pt2 = b'second block:32 bytes of data!!!'
    >>> block1 = t.encrypt_block(pt1)
    >>> t.tweak = block1[:16]              # chain: first half of ciphertext → next tweak
    >>> block2 = t.encrypt_block(pt2)
    >>> ciphertext = block1 + block2
