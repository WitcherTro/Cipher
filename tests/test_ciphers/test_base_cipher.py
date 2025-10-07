import unittest
from src.ciphers.base_cipher import BaseCipher

class TestBaseCipher(unittest.TestCase):

    def setUp(self):
        self.cipher = BaseCipher()

    def test_encode(self):
        # Test the encode method with a sample input
        self.assertEqual(self.cipher.encode("test"), "expected_output")

    def test_decode(self):
        # Test the decode method with a sample input
        self.assertEqual(self.cipher.decode("expected_output"), "test")

if __name__ == '__main__':
    unittest.main()