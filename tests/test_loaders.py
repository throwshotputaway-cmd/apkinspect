import hashlib
import hmac
import io
import unittest
import zipfile
import gzip

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from apkinspect import kfqoq, vbfk, xor_gzip
from apkinspect.common import parse_hex, validate_payload


def kfqoq_blob(plaintext, key, kind, compressed=False):
    payload = gzip.compress(plaintext) if compressed else plaintext
    message = bytes([1 if compressed else 0]) + payload
    salt = b'S' * 16
    nonce = b'N' * 12
    prk = hmac.new(salt, key, hashlib.sha256).digest()
    derived = hmac.new(prk, kind + b'\x01', hashlib.sha256).digest()
    return salt + nonce + AESGCM(derived).encrypt(nonce, message, salt + kind)


class LoaderTests(unittest.TestCase):
    def test_parse_hex_and_validate_payload(self):
        self.assertEqual(parse_hex('00 aa:11', lengths=(3,)), b'\x00\xaa\x11')
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w'):
            pass
        self.assertEqual(validate_payload(buffer.getvalue(), 'apk'), 0)
        self.assertEqual(validate_payload(b'dex\n035\x00', 'dex'), 0)

    def test_kfqoq_key_decoder(self):
        decoded_hex = 'ab' * 32
        prefix = 0x41
        encoded = '41' + ''.join('%02x' % (ord(char) ^ prefix)
                                for char in decoded_hex)
        self.assertEqual(kfqoq.decode_key(encoded), bytes.fromhex(decoded_hex))

    def test_kfqoq_round_trip(self):
        key = b'K' * 32
        kind = kfqoq.kind_byte('H')
        expected = b'dex\n035\x00payload'
        blob = kfqoq_blob(expected, key, kind)
        self.assertEqual(kfqoq.decrypt_blob(blob, key, kind), expected)

    def test_kfqoq_compressed_round_trip(self):
        key = b'C' * 32
        kind = kfqoq.kind_byte('H')
        expected = b'compressed payload'
        blob = kfqoq_blob(expected, key, kind, compressed=True)
        self.assertEqual(kfqoq.decrypt_blob(blob, key, kind), expected)

    def test_vbfk_round_trip(self):
        key = b'V' * 32
        expected = b'PK\x03\x04payload'
        packed = gzip.compress(expected)
        pad = 16 - len(packed) % 16
        packed += bytes([pad]) * pad
        iv = b'I' * 16
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        encrypted = iv + encryptor.update(packed) + encryptor.finalize()
        digest = hashlib.sha256(key).digest()
        transformed = bytes(value ^ digest[index % len(digest)]
                             for index, value in enumerate(encrypted))
        self.assertEqual(vbfk.decrypt_chunks([transformed], key), expected)

    def test_xor_gzip_round_trip(self):
        key = b'X' * 32
        expected = b'dex\n035\x00payload'
        packed = gzip.compress(expected)
        encrypted = bytes(value ^ key[index % len(key)]
                          for index, value in enumerate(packed))
        self.assertEqual(xor_gzip.decrypt_blob(encrypted, key), expected)


if __name__ == '__main__':
    unittest.main()
