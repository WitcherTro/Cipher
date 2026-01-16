from abc import ABC, abstractmethod
from typing import Union, Any

class BaseCipher(ABC):
    @abstractmethod
    def encrypt(self, text: Union[str, bytes, Any]) -> Union[str, bytes, Any]:
        pass

    @abstractmethod
    def decrypt(self, text: Union[str, bytes, Any], **kwargs) -> Union[str, bytes, Any]:
        pass
