
import unittest

from src.main import (
    add_padding,
    decrypt_ecb,
    encrypt_ecb,
    parse_key,
    remove_padding,
)


KEY = parse_key("000102030405060708090a0b0c0d0e0f")


class TestCryptoCore(unittest.TestCase):

    def test_encrypt_decrypt_text(self):
        original = b"Hello CryptoCore!"
        encrypted = encrypt_ecb(original, KEY)
        decrypted = decrypt_ecb(encrypted, KEY)
        self.assertEqual(decrypted, original)

    def test_empty_data(self):
        original = b""
        encrypted = encrypt_ecb(original, KEY)
        decrypted = decrypt_ecb(encrypted, KEY)
        self.assertEqual(decrypted, original)

    def test_binary_data(self):
        original = bytes(range(256))
        encrypted = encrypt_ecb(original, KEY)
        decrypted = decrypt_ecb(encrypted, KEY)
        self.assertEqual(decrypted, original)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            parse_key("1234")

    def test_invalid_hex_key(self):
        with self.assertRaises(ValueError):
            parse_key("z" * 32)

    def test_invalid_ciphertext_length(self):
        with self.assertRaises(ValueError):
            decrypt_ecb(b"short", KEY)

    def test_invalid_padding(self):
        with self.assertRaises(ValueError):
            remove_padding(b"A" * 15 + b"\x00")


if __name__ == "__main__":
    unittest.main()
