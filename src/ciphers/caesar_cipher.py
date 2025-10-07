from .base_cipher import BaseCipher

class CaesarCipher(BaseCipher):
    def __init__(self, shift: int = 3):
        self.shift = shift % 26

    def encrypt(self, text: str) -> str:
        result = ""
        for char in text.upper():
            if char.isalpha():
                ascii_offset = ord('A')
                shifted = (ord(char) - ascii_offset + self.shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        return result

    def decrypt(self, text: str) -> str:
        self.shift = -self.shift
        result = self.encrypt(text)
        self.shift = -self.shift  # Reset shift
        return result