from collections import Counter
from typing import Union, Any
from ciphers.base_cipher import BaseCipher
from tools.frequency_analyzer import FrequencyAnalyzer

class VigenereCipher(BaseCipher):
    def __init__(self, key: str = ""):
        self.key = key.upper()
        self.analyzer = FrequencyAnalyzer()


    def encrypt(self, text: Union[str, Any]) -> str:
        if not isinstance(text, str):
            raise ValueError("Vigenere Cipher only supports string input")

        if not self.key:
            raise ValueError("Key is required for encryption")
        result = []
        key_index = 0
        key_length = len(self.key)
        
        for char in text.upper():
            if 'A' <= char <= 'Z':
                shift = ord(self.key[key_index % key_length]) - ord('A')
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                result.append(encrypted_char)
                key_index += 1
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, text: Union[str, Any], **kwargs) -> str:
        if not isinstance(text, str):
            raise ValueError("Vigenere Cipher only supports string input")

        if kwargs.get('crack', False):
             return self.crack_cipher(text)

        result = []
        key_index = 0
        key_length = len(self.key)

        for char in text.upper():
            if 'A' <= char <= 'Z':
                shift = ord(self.key[key_index % key_length]) - ord('A')
                decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                result.append(decrypted_char)
                key_index += 1
            else:
                result.append(char)
        return "".join(result)

    def crack_cipher(self, text: str) -> str:
        """Attempt to crack the cipher without a key."""
        cleaned_text = "".join([c for c in text.upper() if 'A' <= c <= 'Z'])
        if not cleaned_text:
            return "Error: No valid ciphertext provided."

        best_cand = None
        best_score = -1

        # Check IoC for key lengths 2 to 25
        candidates = []
        for length in range(2, 26):
            avg_ioc = self._calculate_avg_ioc(cleaned_text, length)
            # Heuristic: IoC closer to 0.06 is better (for English/Slovak)
            candidates.append((length, avg_ioc))

        candidates.sort(key=lambda x: x[1], reverse=True)
        # Take the best length
        key_len = candidates[0][0]
        
        # Try finding key for both languages
        eng_probs = self.analyzer.get_ordered_probabilities('english')
        svk_probs = self.analyzer.get_ordered_probabilities('slovak')
        
        key_eng, score_eng = self._solve_key(cleaned_text, key_len, eng_probs)
        key_svk, score_svk = self._solve_key(cleaned_text, key_len, svk_probs)
        
        if score_eng < score_svk:
            final_key = key_eng
            lang = "English"
        else:
            final_key = key_svk
            lang = "Slovak"
            
        print(f"[Analysis] Detected Key Length: {key_len}")
        print(f"[Analysis] Detected Language: {lang}")
        print(f"[Analysis] Found Key: {final_key}")
        
        # Set the key so the instance is usable
        self.key = final_key
        return self.decrypt(text)

    def _calculate_avg_ioc(self, text: str, length: int) -> float:
        total_ioc = 0
        for i in range(length):
            segment = text[i::length]
            total_ioc += self._calculate_ioc(segment)
        return total_ioc / length

    def _calculate_ioc(self, text: str) -> float:
        N = len(text)
        if N <= 1: return 0
        counts = Counter(text)
        sum_n_nm1 = sum(c * (c - 1) for c in counts.values())
        return sum_n_nm1 / (N * (N - 1))

    def _solve_key(self, text: str, key_len: int, target_probs: list) -> tuple[str, float]:
        found_key = []
        total_chi_sq = 0
        
        for i in range(key_len):
            segment = text[i::key_len]
            shift, score = self._solve_caesar_shift(segment, target_probs)
            found_key.append(chr(shift + ord('A')))
            total_chi_sq += score
            
        return "".join(found_key), total_chi_sq

    def _solve_caesar_shift(self, segment: str, target_probs: list) -> tuple[int, float]:
        best_shift = 0
        min_chi_dist = float('inf')
        N = len(segment)
        counts = Counter(segment)
        
        for shift in range(26):
            chi_dist = 0
            for char_code in range(26):
                # We hypothesise that if we decrypt with 'shift', resulting distribution matches target
                # Decrypted char 'D' comes from Cipher char 'C' = (D + shift)
                
                c_char = chr(((char_code + shift) % 26) + ord('A'))
                obs = counts.get(c_char, 0)
                exp = N * target_probs[char_code]
                
                chi_dist += ((obs - exp) ** 2) / (exp if exp > 0 else 1e-9)
                
            if chi_dist < min_chi_dist:
                min_chi_dist = chi_dist
                best_shift = shift
                
        return best_shift, min_chi_dist
