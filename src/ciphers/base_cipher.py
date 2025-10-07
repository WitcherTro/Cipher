from abc import ABC, abstractmethod

class BaseCipher(ABC):
    @abstractmethod
    def encrypt(self, text: str) -> str:
        pass

    @abstractmethod
    def decrypt(self, text: str, known_shift: bool = True) -> str:
        pass