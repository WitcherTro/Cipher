from typing import Dict, Type, Any, Optional
from handlers.base_handler import BaseHandler
from handlers.vigenere_handler import VigenereHandler
from handlers.hill_handler import HillHandler
from handlers.stream_handler import StreamHandler
from handlers.rsa_handler import RSAHandler

class DefaultHandler(BaseHandler):
    def get_config_params(self, intent: str = "general") -> Dict[str, Any]:
        return {}

    def crack_ui(self, cipher_instance, initial_input: Optional[str] = None) -> None:
        print("[!] Automated cracking is not currently supported for this cipher type.")

class HandlerFactory:
    _handlers: Dict[str, Type[BaseHandler]] = {
        "vigenere": VigenereHandler,
        "hill": HillHandler,
        "stream": StreamHandler,
        "rsa": RSAHandler
    }

    @classmethod
    def get_handler(cls, cipher_name: str) -> BaseHandler:
        """Return a handler instance for the given cipher name"""
        handler_class = cls._handlers.get(cipher_name.lower())
        if not handler_class:
            return DefaultHandler()
        return handler_class()
