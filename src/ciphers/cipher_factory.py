from typing import Dict, Type
from ciphers.base_cipher import BaseCipher
from ciphers.caesar_cipher import CaesarCipher

class CipherFactory:
    _ciphers: Dict[str, Type[BaseCipher]] = {
        "caesar": CaesarCipher
    }

    @classmethod
    def get_cipher(cls, cipher_name: str, **kwargs) -> BaseCipher:
        """Create and return a cipher instance by name"""
        cipher_class = cls._ciphers.get(cipher_name.lower())
        if not cipher_class:
            raise ValueError(f"Unknown cipher: {cipher_name}. Available ciphers: {', '.join(cls._ciphers.keys())}")
        return cipher_class(**kwargs)

    @classmethod
    def get_available_ciphers(cls) -> list:
        """Return list of available cipher names"""
        return list(cls._ciphers.keys())