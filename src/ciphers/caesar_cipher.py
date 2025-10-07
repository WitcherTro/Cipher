from ciphers.base_cipher import BaseCipher
from tools.frequency_analyzer import FrequencyAnalyzer

class CaesarCipher(BaseCipher):
    def __init__(self, shift: int = 3, language: str = "english"):
        self.shift = shift % 26
        self.analyzer = FrequencyAnalyzer(language)

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

    def decrypt(self, text: str, known_shift: bool = True) -> str:
        if known_shift:
            temp_shift = self.shift
            self.shift = -self.shift % 26
            result = self.encrypt(text)
            self.shift = temp_shift
            return result
        else:
            return self.crack_cipher(text)

    def crack_cipher(self, text: str) -> str:
        """Try frequency analysis first, if uncertain use bruteforce"""
        # Try frequency analysis
        best_score = float('inf')
        best_shift = 0
        best_text = ""

        for test_shift in range(26):
            self.shift = test_shift
            decrypted = self.decrypt(text, known_shift=True)
            frequencies = self.analyzer.analyze_text(decrypted)
            score = self.analyzer.compare_to_language(frequencies)
            
            if score < best_score:
                best_score = score
                best_shift = test_shift
                best_text = decrypted

        self.shift = best_shift
        return best_text

    def bruteforce(self, text: str) -> list:
        """Return all possible shifts and their results"""
        results = []
        for shift in range(26):
            self.shift = shift
            decrypted = self.decrypt(text, known_shift=True)
            results.append((shift, decrypted))
        return results

    def set_language(self, language: str):
        """Change the language for frequency analysis"""
        self.analyzer.set_language(language)