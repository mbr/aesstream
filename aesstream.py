#!/usr/bin/env python
# coding=utf8

import os
from io import IOBase

import M2Crypto

AES_BLOCKSIZE = 16
AES_KEYLENGTH = 16
AES_CIPHER = 'aes_128_cfb'

_OPENSSL_ENCRYPT = 1
_OPENSSL_DECRYPT = 0

class AESStreamWriter(IOBase):
	def __init__(self, key, ostream, iv = None):
		if not iv: iv = os.urandom(AES_BLOCKSIZE)
		assert(len(iv) == AES_BLOCKSIZE)
		assert(len(key) == AES_KEYLENGTH)

		key = str(key)
		self.ostream = ostream
		self.aes = M2Crypto.EVP.Cipher(alg = AES_CIPHER, key = key, iv = iv, op = _OPENSSL_ENCRYPT)

		self.ostream.write(iv)

	def write(self, data):
		self.ostream.write(self.aes.update(str(data)))

	def close(self):
		self.ostream.write(self.aes.final())
		super(AESStreamWriter, self).close()


class AESStreamReader(IOBase):
	def __init__(self, key, istream):
		self.istream = istream
		iv = self.istream.read(AES_KEYLENGTH)

		self.aes = M2Crypto.EVP.Cipher(alg = AES_CIPHER, key = key, iv = iv, op = _OPENSSL_DECRYPT)

	def read(self, *args, **kwargs):
		# aes_128_cfb is one byte in => one byte out
		# that's why this is safe
		return self.aes.update(self.istream.read(*args, **kwargs))


if '__main__' == __name__:
	import unittest
	from cStringIO import StringIO
	from binascii import hexlify

	class AESStreamTests(unittest.TestCase):
		def test_enc_dev(self):
			key = 'somekey012345678'
			cleartext = 'The io module provides the Python interfaces to stream handling. Under Python 2.x, this is proposed as an alternative to the built-in file object, but in Python 3.x it is the default interface to access files and streams.' * 1000

			output_stream = StringIO()
			with AESStreamWriter(key, output_stream) as s:
				s.write(cleartext)

			ciphertext = output_stream.getvalue()

			with AESStreamReader(key, StringIO(ciphertext)) as s:
				self.assertEqual(cleartext, s.read())

			badkey = key[:AES_KEYLENGTH-1] + 'x'
			with AESStreamReader(badkey, StringIO(ciphertext)) as s:
				self.assertNotEqual(cleartext, s.read())

		def test_known_values(self):
			expected_ciphertext = '\xc2L-6cE#\x0cI\x81,\x92y'
			expected_cleartext = 'my cleartext\n'
			key = 'test1234....AAAA'
			iv = 'opqrstuvwxyzABCD'

			data = iv + expected_ciphertext

			with AESStreamReader(key, StringIO(data)) as s:
				self.assertEqual(s.read(), expected_cleartext)

			buf = StringIO()
			with AESStreamWriter(key, buf, iv = iv) as s:
				s.write(expected_cleartext)
				new_data = buf.getvalue()

			self.assertEqual(iv + expected_ciphertext, new_data)

	unittest.main()
