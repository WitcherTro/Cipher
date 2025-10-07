from abc import ABC, abstractmethod

class BaseCipher(ABC):
    """Base class for all cipher implementations"""
    
    @abstractmethod
    def encrypt(self, text: str) -> str:
        """Encrypt the given text"""
        pass
    
    @abstractmethod
    def decrypt(self, text: str) -> str:
        """Decrypt the given text"""
        pass