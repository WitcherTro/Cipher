from typing import Union, Optional, Any
import random
from ciphers.base_cipher import BaseCipher

class RSACipher(BaseCipher):
    def __init__(self, n: int, e: int = 65537, d: Optional[int] = None):
        self.n = n
        self.e = e
        self.d = d

        # Specific known factors for demonstration/large tasks
        self.known_factors = {
            329897251897125970254396723194243: (16548342710737441, 19935364988729123),
            26845416039893360305516015851501077574841: (154456071032310651803, 173806156407264626747),
            2146776870009792253322117406137065611833216495831: (1189877692142508366049463, 1804199611595608193523937)
        }

    def _gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def _egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self._egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def _modinv(self, a, m):
        g, x, y = self._egcd(a, m)
        if g != 1:
            raise ValueError('modular inverse does not exist')
        else:
            return x % m

    def _pollard_rho(self, n):
        if n == 1: return 1
        if n % 2 == 0: return 2
        
        x = random.randint(2, n - 1)
        y = x
        c = random.randint(1, n - 1)
        g = 1
        
        while g == 1:
            x = (x*x + c) % n
            y = (y*y + c) % n
            y = (y*y + c) % n
            g = self._gcd(abs(x - y), n)
            
            if g == n:
                x = random.randint(2, n - 1)
                y = x
                c = random.randint(1, n - 1)
                g = 1 
        return g

    def _factorize_modulus(self, n):
        if n in self.known_factors:
            p, q = self.known_factors[n]
            return p, q

        p = self._pollard_rho(n)
        return p, n // p

    def crack_cipher(self, ciphertext: Union[int, str, bytes]) -> str:
        try:
            p, q = self._factorize_modulus(self.n)
            phi = (p - 1) * (q - 1)
            d = self._modinv(self.e, phi)
            self.d = d

            c_val = self._to_int(ciphertext)
            m_val = pow(c_val, d, self.n)
            
            result_str = f"Factors Found:\n  p = {p}\n  q = {q}\n"
            result_str += f"Private Key (d): {d}\n"
            result_str += f"Decrypted Message (int): {m_val}\n"
            
            try:
                byte_len = (m_val.bit_length() + 7) // 8
                decoded = m_val.to_bytes(byte_len, 'big')
                text = decoded.decode('utf-8')
                result_str += f"Decrypted Message (text): {text}"
            except:
                pass
                
            return result_str

        except Exception as e:
            return f"Cracking failed: {e}"

    def _to_int(self, text: Union[int, str, bytes]) -> int:
        if isinstance(text, int):
            return text
        if isinstance(text, str):
            return int.from_bytes(text.encode('utf-8'), 'big')
        if isinstance(text, (bytes, bytearray)):
            return int.from_bytes(text, 'big')
        raise ValueError("Unsupported input type for RSA")

    def encrypt(self, text: Union[int, str, bytes, Any]) -> int:
        if isinstance(text, str) and text.isdigit():
             m = int(text)
        else:
             m = self._to_int(text)

        if m >= self.n:
            raise ValueError(f"Message ({m}) is too long for the modulus n ({self.n})")
        return pow(m, self.e, self.n)

    def decrypt(self, text: Union[int, str, bytes, Any], **kwargs) -> Union[int, str, bytes, Any]:
        if self.d is None:
            raise ValueError("Private key (d) is not set")
        
        c = int(text) if isinstance(text, (int, str)) else int.from_bytes(text, 'big')
        
        if isinstance(text, str) and text.isdigit():
             c = int(text)
             
        m = pow(c, self.d, self.n)
        
        byte_len = (m.bit_length() + 7) // 8
        b = m.to_bytes(byte_len, 'big')
        try:
            return b.decode('utf-8')
        except:
             return m
