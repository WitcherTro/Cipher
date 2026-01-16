from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseHandler(ABC):
    """
    Abstract base class for Cipher User Interface handlers.
    Responsible for collecting parameters and managing specific UI flows (cracking).
    """

    @property
    def can_crack(self) -> bool:
        """Override to return True if this handler supports cracking UI."""
        return False

    @abstractmethod
    def get_config_params(self, intent: str = "general") -> Dict[str, Any]:
        """
        Collect necessary parameters from the user for the cipher.
        intent can be 'encrypt', 'decrypt', or 'general'.
        """
        return {}

    def get_default_params(self) -> Dict[str, Any]:
        """
        Return default parameters for checking initialization.
        """
        return {}


    def encrypt_ui(self, cipher_instance) -> None:
        """
        Handle the UI flow for encryption (Input -> Encrypt -> Output).
        Default implementation handles simple text input.
        """
        text = input("Enter text/data to encrypt: ")
        try:
            result = cipher_instance.encrypt(text)
            print(f"\n[=] Encrypted Result: {result}")
        except Exception as e:
            print(f"[!] Encryption failed: {e}")

    def decrypt_ui(self, cipher_instance) -> None:
        """
        Handle the UI flow for decryption (Input -> Decrypt -> Output).
        Default implementation handles simple text input.
        """
        text = input("Enter text/data to decrypt: ")
        try:
            result = cipher_instance.decrypt(text)
            print(f"\n[=] Decrypted Result: {result}")
        except NotImplementedError:
            print("[!] This cipher does not support decryption (e.g. Hash).")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")

    @abstractmethod
    def crack_ui(self, cipher_instance, initial_input: Optional[str] = None) -> None:
        """
        Handle the UI flow for cracking/analyzing the cipher.
        """
        print("[!] Cracking UI not implemented for this cipher.")
