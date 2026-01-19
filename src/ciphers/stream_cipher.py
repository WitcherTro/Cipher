from typing import Union, Any, List
from ciphers.base_cipher import BaseCipher

class StreamCipher(BaseCipher):
    def __init__(self, password: str):
        self.password = password
        self.key = self._get_key(password)

    def _get_key(self, passwd: str) -> List[int]:
        rc4_k = [0] * 256
        passwd_with_null = passwd + '\0'
        j = 0
        for i in range(256):
            rc4_k[i] = ord(passwd_with_null[j])
            if passwd_with_null[j] != '\0':
                j += 1
            else:
                j = 0
        return rc4_k

    def _rc4_init(self, key: List[int]) -> List[int]:
        rc4_s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + rc4_s[i] + key[i]) % 256
            rc4_s[i], rc4_s[j] = rc4_s[j], rc4_s[i]
        return rc4_s

    def _rc4_rand(self, rc4_s, rc4_i, rc4_j):
        rc4_i = (rc4_i + 1) % 256
        rc4_j = (rc4_j + rc4_s[rc4_i]) % 256
        rc4_s[rc4_i], rc4_s[rc4_j] = rc4_s[rc4_j], rc4_s[rc4_i]
        t = (rc4_s[rc4_i] + rc4_s[rc4_j]) % 256
        return rc4_s[t], rc4_i, rc4_j

    def encrypt(self, text: Union[str, bytes]) -> bytes:
        if isinstance(text, str):
            data = text.encode('utf-8')
        else:
            data = text

        rc4_s = self._rc4_init(self.key)
        rc4_i = 0
        rc4_j = 0
        cipher_text = bytearray()
        
        for p in data:
            r, rc4_i, rc4_j = self._rc4_rand(rc4_s, rc4_i, rc4_j)
            c = p ^ r
            cipher_text.append(c)
        
        return bytes(cipher_text)

    def decrypt(self, text: Union[str, bytes], **kwargs) -> bytes:
        return self.encrypt(text)

    def crack_cipher(self, text: bytes) -> str:
        if not isinstance(text, (bytes, bytearray)):
            raise TypeError("crack_cipher expects ciphertext as bytes")

        text_bytes = bytes(text)

        check_len = min(len(text_bytes), 60)
        cipher_sample = text_bytes[:check_len]

        print("[*] Starting brute-force (100000-999999)...")
        get_key = self._get_key
        rc4_init = self._rc4_init
        
        for pin in range(100000, 1000000):
            if pin % 100000 == 0:
                print(f"... checking {pin} ...")

            passwd = str(pin)
            key = get_key(passwd)
            
            s = list(range(256))
            j = 0
            for i_init in range(256):
                j = (j + s[i_init] + key[i_init]) % 256
                s[i_init], s[j] = s[j], s[i_init]
            
            i = 0
            j = 0
            valid = True
            decrypted_sample = bytearray()
            
            for k in range(check_len):
                i = (i + 1) % 256
                j = (j + s[i]) % 256
                s[i], s[j] = s[j], s[i]
                t = (s[i] + s[j]) % 256
                
                p_byte = cipher_sample[k] ^ s[t]
                
                if p_byte < 9 or (14 <= p_byte < 32) or p_byte == 127:
                    valid = False
                    break
                decrypted_sample.append(p_byte)
            
            if valid:
                try:
                    found_text = decrypted_sample.decode('utf-8')
                    self.password = passwd
                    self.key = key
                    msg = f"FOUND PIN: {pin}\nPartial Decryption: {found_text}..."
                    return msg
                except:
                    continue

        return "Crack failed. No valid PIN found."
