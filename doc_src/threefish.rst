Threefish block cipher
======================

.. function:: skein.threefish(key, tweak)

    This constructor function returns a cipher object for encryption and
    decryption with the given key and tweak values.
    The key must be a bytes object of length 32, 64, or 128,
    while the tweak must always consist of 16 bytes.


Threefish objects
-----------------

Threefish cipher objects have two methods:

.. method:: threefish.encrypt_block(data)

    Encrypt the given block of (bytes) data.
    (String data has to be encoded to bytes first.)
    The block has to have the same length as the key,
    i.e. 32, 64, or 128 bytes.

.. method:: threefish.decrypt_block(data)

    Decrypt the given block of (bytes) data.
    The block has to have the same length as the key,
    i.e. 32, 64, or 128 bytes.


In addition they have the following attributes:

.. attribute:: threefish.tweak

    The tweak value given to the constructor function.
    This attribute is writable, allowing the tweak to be changed without
    creation of a new cipher object.

.. attribute:: threefish.block_bits

    Threefish block size (as determined by the key length) in bits, i.e.
    ``256``, ``512``, or ``1024``

.. attribute:: threefish.block_size

    Threefish block size in bytes (same as the key length), i.e.
    ``32``, ``64``, or ``128``


Examples
--------

Encryption and decryption of a block of 32 bytes::

    >>> from skein import threefish
    >>> t = threefish(b'key of 32,64 or 128 bytes length', b'tweak: 16 bytes ')
    >>> t.block_size, t.block_bits
    (32, 256)
    >>> c = t.encrypt_block(b'block of data,same length as key')
    >>> c
    b'\x1c\xbf\x83\xbeoW\xd8\xe0f\xba\xb2\xea\x0e\x91\x0b\n\x06,\xd5:\x97\x9a\x11IaEGM\xc0\xe8\x9e\x86'
    >>> t.decrypt_block(c)
    b'block of data,same length as key'


Changing the tweak leads to a different cipher text::

    >>> t.tweak = b'some other tweak'
    >>> c = t.encrypt_block(b'block of data,same length as key')
    >>> c
    b'3gE(9X|_\xab\x87\xe5\xc7\xcc\xa6m\xc4e\x06\xcb\xdbBg\xf2\xe6A\xb9\x86o\xecW\xe6\xfd'
    >>> t.decrypt_block(c)
    b'block of data,same length as key'

