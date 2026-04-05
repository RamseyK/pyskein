Skein Stream Cipher
===================

:class:`skein.StreamCipher` implements a synchronous stream cipher using
Skein's extendable output function (XOF) property.  A key (and optional
nonce) is hashed into Skein's state; the resulting keystream is produced
by running Threefish in counter mode over that state.  Encryption is
XOR of the plaintext with the keystream, so the same cipher object
can decrypt by calling ``encrypt`` again (or the ``decrypt`` alias).

Because Skein allows arbitrary output length, the keystream is unlimited:
you can encrypt any number of bytes without needing to re-key.

.. class:: skein.StreamCipher(key, nonce=b'', hasher=skein512)

    Create a new stream cipher.

    ``key`` is the secret key as a bytes object.  Any length is accepted;
    it is processed through Skein's MAC key input, so longer keys are
    handled securely.

    ``nonce`` is an optional bytes value that is incorporated via Skein's
    nonce input type, making the keystream unique even if the same key is
    reused.  Pass a different nonce for each message encrypted under the
    same key.

    ``hasher`` selects the Skein variant (``skein256``, ``skein512``, or
    ``skein1024``).  Defaults to ``skein512``.

.. method:: StreamCipher.keystream(n)

    Return the next ``n`` bytes of the keystream as a bytes object, and
    advance the stream position by ``n``.  Subsequent calls continue from
    where the previous call left off.

.. method:: StreamCipher.encrypt(plain)

    XOR ``plain`` (bytes) with the next ``len(plain)`` bytes of the
    keystream and return the result.

.. method:: StreamCipher.decrypt(cipher)

    Alias for :meth:`encrypt`.  Because XOR is its own inverse, the same
    operation encrypts and decrypts, provided both sides use the same key,
    nonce, and stream position.

    Always create a fresh :class:`StreamCipher` (or call :meth:`keystream`
    to seek) to decrypt from the beginning of the stream.


Example::

    >>> import skein
    >>> sc = skein.StreamCipher(b"secret", nonce=b"unique-per-msg")
    >>> ciphertext = sc.encrypt(b"squeamish ossifrage")
    >>> ciphertext
    b'...'

    >>> # decrypt with a fresh cipher at the same stream position:
    >>> sc2 = skein.StreamCipher(b"secret", nonce=b"unique-per-msg")
    >>> sc2.decrypt(ciphertext)
    b'squeamish ossifrage'

Encrypting two messages in sequence under the same key requires a
different nonce for each, or the keystream positions will overlap and
cancel out::

    >>> # wrong: reusing the same cipher object for two independent messages
    >>> sc = skein.StreamCipher(b"secret")
    >>> c1 = sc.encrypt(b"message one")
    >>> c2 = sc.encrypt(b"message two")   # stream continues from end of c1

    >>> # correct: fresh cipher (or distinct nonce) per message
    >>> sc1 = skein.StreamCipher(b"secret", nonce=b"msg1")
    >>> sc2 = skein.StreamCipher(b"secret", nonce=b"msg2")
    >>> c1 = sc1.encrypt(b"message one")
    >>> c2 = sc2.encrypt(b"message two")
