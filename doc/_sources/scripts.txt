Demo Scripts
============

There are two Python scripts included in the distribution which demonstrate
Skein hashing and Threefish encryption with PySkein.
Please note that both scripts are written for demonstration
of the functionality of PySkein only. I do not claim that they are
secure or fit for any other purpose.


skeinsum
--------

This script does its best to mimic the behaviour of the well known tools
`md5sum`, `sha1sum` or `sha256sum`.  It hashes all specified files with
Skein-512-256 and prints the resulting hexdigest. ::

    $ skeinsum COPYING
    63fb45390c188b7ba0e8eb2ed0e2fefa8416da515f0b28e670345ecd0de673dc  COPYING


threefish
---------

With this script you can try out file encryption and decryption with
Threefish in a variant of tweak block chaining mode. This mode is designed
for tweakable block ciphers, using an encrypted block as tweak value for the
encryption of the next block.

Since Threefish has a block size of 32, 64 or 128 bytes and a tweak size of
16 bytes, tweak block chaining cannot be implemented without modification.
The script runs Threefish with a block size of 32 bytes and uses the first
16 bytes of an encrypted block as tweak value for the next encryption.
A random initial tweak value is used (and saved together with the encrypted
file).

To encrypt the last block of the file, random bytes are appended to pad it
to the block size of 32 bytes. The original length of the block is then
encoded in the 5 least significant bits of the last byte of the block.

Note that there is no obvious way to verify whether the key used for
decryption is correct or not. Decryption will always succeed and produce
garbage in the case of a wrong key. This is good enough for demonstration
purposes (and may even be desired in some circumstances) and could trivially
be changed by using checksums anyway.

The 256 bit key value is derived by hashing the password entered at the command
line with Skein-512-256. ::

        $ threefish encrypt README
        Password:
        $ ls README*
        README  README.3f
        $ mv README README.orig
        $ threefish decrypt README.3f
        Password:
        $ diff README README.orig
        $

