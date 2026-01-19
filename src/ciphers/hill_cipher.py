import numpy as np
from typing import List, Union, Optional, Any
from ciphers.base_cipher import BaseCipher

class HillCipher(BaseCipher):
    def __init__(self, key_matrix: Optional[Union[List[List[int]], np.ndarray]] = None):
        if key_matrix is not None:
            self.key_matrix = np.array(key_matrix)
            self.n = self.key_matrix.shape[0]
            if self.key_matrix.shape[0] != self.key_matrix.shape[1]:
                raise ValueError("Key matrix must be square")
        else:
            self.key_matrix = None
            self.n = 0

    def _char_to_num(self, c: str) -> int:
        return ord(c.upper()) - ord('A')

    def _num_to_char(self, n: int) -> str:
        return chr((n % 26) + ord('A'))

    def encrypt(self, text: Union[str, Any]) -> str:
        if not isinstance(text, str):
            raise ValueError("Hill Cipher only supports string input")
        
        if self.key_matrix is None:
            raise ValueError("Key matrix not set.")
            
        text = "".join([c for c in text.upper() if 'A' <= c <= 'Z'])
        padding_len = (self.n - len(text) % self.n) % self.n
        text += 'X' * padding_len
        
        ciphertext = ""
        for i in range(0, len(text), self.n):
            chunk = text[i:i+self.n]
            vector = np.array([self._char_to_num(c) for c in chunk])
            encrypted_vector = np.dot(self.key_matrix, vector) % 26
            ciphertext += "".join([self._num_to_char(num) for num in encrypted_vector])
            
        return ciphertext

    def decrypt(self, text: Union[str, Any], **kwargs) -> str:
        if not isinstance(text, str):
            raise ValueError("Hill Cipher only supports string input")

        if kwargs.get('crack', False):
             crib = kwargs.get('crib', '')
             if not crib:
                 raise ValueError("Crib (known plaintext) required for Hill cracking.")
             return self.crack_cipher(text, crib)
        
        if self.key_matrix is None:
            raise ValueError("Key matrix not set.")

        det = int(round(np.linalg.det(self.key_matrix)))
        try:
            det_inv = pow(det, -1, 26)
        except ValueError:
             raise ValueError("Key matrix is not invertible modulo 26")

        adjugate = np.round(det * np.linalg.inv(self.key_matrix)).astype(int) % 26
        key_matrix_inv = (det_inv * adjugate) % 26
        
        decrypted_text = ""
        text_filtered = "".join([c for c in text.upper() if 'A' <= c <= 'Z'])
        
        if len(text_filtered) % self.n != 0:
             pass

        for i in range(0, len(text_filtered), self.n):
            chunk = text_filtered[i:i+self.n]
            if len(chunk) < self.n: continue
            
            vector = np.array([self._char_to_num(c) for c in chunk])
            decrypted_vector = np.dot(key_matrix_inv, vector) % 26
            decrypted_text += "".join([self._num_to_char(num) for num in decrypted_vector])
            
        return decrypted_text

    def crack_cipher(self, ciphertext: str, crib: str) -> str:
        crib = "".join([c for c in crib.upper() if 'A' <= c <= 'Z'])
        ciphertext = "".join([c for c in ciphertext.upper() if 'A' <= c <= 'Z'])
        
        l = len(crib)
        n = int(l ** 0.5)

        if n * n != l:
            if n < 2:
                raise ValueError(f"Crib too short. Length {l} not usable.")
            new_l = n * n
            print(f"[!] Warning: Crib length {l} is not a square. Shortening to first {new_l} characters.")
            crib = crib[:new_l]
            l = new_l
        
        if len(ciphertext) < l:
            raise ValueError("Ciphertext is shorter than crib.")

        P_cols = []
        C_cols = []
        
        for i in range(0, l, n):
            p_chunk = crib[i:i+n]
            c_chunk = ciphertext[i:i+n]
            P_cols.append([self._char_to_num(c) for c in p_chunk])
            C_cols.append([self._char_to_num(c) for c in c_chunk])
            
        P = np.array(P_cols).T
        C = np.array(C_cols).T
        
        try:
            det = int(round(np.linalg.det(P)))
            det_inv = pow(det, -1, 26)
        except ValueError:
            raise ValueError("Crib matrix P is not invertible mod 26. Try a different crib.")
            
        adjugate = np.round(det * np.linalg.inv(P)).astype(int) % 26
        P_inv = (det_inv * adjugate) % 26
        
        K = np.dot(C, P_inv) % 26
        
        print(f"[Analysis] Found Key Matrix for n={n}:\n{K}")
        self.key_matrix = K
        self.n = n
        
        return self.decrypt(ciphertext)

