#!/usr/bin/env python
# coding=utf8

import os
from io import IOBase

import M2Crypto
from M2Crypto.m2 import AES_BLOCK_SIZE

AES_VALID_KEYLENGTHS = (128, 196, 256)
AES_VALID_CIPHER_MODES = ('cbc', 'ecb', 'cfb', 'ofb')
DEFAULT_ALGO = 'aes_128_cfb'


class CipherStreamBase(object):
    def parse_cipher_identifier(self, s):
        def _exc(msg):
            raise ValueError('Invalid cipher identifier: %s. %s' % (s, msg))
        if not 11 == len(s):
            _exc('Must be 11 characters long')

        if not s.startswith('aes'):
            raise _exc('Must start with "aes"')

        keylen = int(s[4:7])
        if not keylen in AES_VALID_KEYLENGTHS:
            raise _exc('Keylength must be one of %r' % (AES_VALID_KEYLENGTHS,))

        mode = s[8:].lower()
        if not mode in AES_VALID_CIPHER_MODES:
            raise _exc('Mode must be one of %r' % (AES_VALID_CIPHER_MODES,))

        self.block_size = AES_BLOCK_SIZE
        self.keylen = int(keylen/8)
        self.mode = mode
        self.cipher = 'aes'
        self.full_cipher = s.lower()

    def set_iv(self, iv=None):
        if not iv:
            iv = os.urandom(self.block_size)
        elif not len(iv) == self.block_size:
            raise Exception(
                'Initialization Vector must be equal to block size (%d)' \
                % self.block_size
            )
        self.iv = iv

    def set_key(self, key):
        if not len(key) == self.keylen:
            raise Exception(
                'Key must be (%d) bits for %s.' % \
                (self.keylen*8, self.full_cipher)
            )
        self.key = key


class AESStreamWriter(IOBase, CipherStreamBase):
    def __init__(self, key, ostream, iv=None, algo=DEFAULT_ALGO):
        self.parse_cipher_identifier(algo)
        self.ostream = ostream

        self.set_iv(iv)
        self.set_key(key)

        self.aes = M2Crypto.EVP.Cipher(
            alg=self.full_cipher,
            key=self.key,
            iv=self.iv,
            op=M2Crypto.m2.encrypt
        )

        self.ostream.write(self.iv)

    def write(self, data):
        self.ostream.write(self.aes.update(data))

    def close(self):
        self.ostream.write(self.aes.final())
        super(AESStreamWriter, self).close()


class AESStreamReader(IOBase, CipherStreamBase):
    def __init__(self, key, istream, algo=DEFAULT_ALGO):
        self.parse_cipher_identifier(algo)
        self.istream = istream

        self.iv = self.istream.read(self.keylen)
        self.set_key(key)

        self.aes = M2Crypto.EVP.Cipher(
            alg=self.full_cipher,
            key=self.key,
            iv=self.iv,
            op=M2Crypto.m2.decrypt
        )

    def read(self, *args, **kwargs):
        # stream cipher: one byte in => one byte out
        # that's why this is safe
        return self.aes.update(self.istream.read(*args, **kwargs))


if '__main__' == __name__:
    import unittest
    from io import BytesIO
    from binascii import hexlify

    AES_KEYLENGTH = int(128/8)

    class AESStreamTests(unittest.TestCase):
        def test_enc_dev(self):
            key = b'somekey012345678'
            cleartext = b'The io module provides the Python interfaces to stream handling. Under Python 2.x, this is proposed as an alternative to the built-in file object, but in Python 3.x it is the default interface to access files and streams.' * 1000

            output_stream = BytesIO()
            with AESStreamWriter(key, output_stream) as s:
                s.write(cleartext)

            ciphertext = output_stream.getvalue()

            with AESStreamReader(key, BytesIO(ciphertext)) as s:
                self.assertEqual(cleartext, s.read())

            badkey = key[:AES_KEYLENGTH-1] + b'x'
            with AESStreamReader(badkey, BytesIO(ciphertext)) as s:
                self.assertNotEqual(cleartext, s.read())

        def test_known_values(self):
            expected_ciphertext = b'\xc2L-6cE#\x0cI\x81,\x92y'
            expected_cleartext = b'my cleartext\n'
            key = b'test1234....AAAA'
            iv = b'opqrstuvwxyzABCD'

            data = iv + expected_ciphertext

            with AESStreamReader(key, BytesIO(data)) as s:
                self.assertEqual(s.read(), expected_cleartext)

            buf = BytesIO()
            with AESStreamWriter(key, buf, iv = iv) as s:
                s.write(expected_cleartext)
                new_data = buf.getvalue()

            self.assertEqual(iv + expected_ciphertext, new_data)

    unittest.main()
