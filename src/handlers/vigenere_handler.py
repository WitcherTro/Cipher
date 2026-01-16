import os
from typing import Dict, Any, Optional
from handlers.base_handler import BaseHandler
from tools.ui_utils import browse_file

class VigenereHandler(BaseHandler):
    @property
    def can_crack(self) -> bool:
        return True

    def get_config_params(self, intent: str = "general") -> Dict[str, Any]:
        params = {}
        # For encryption/decryption we usually need a key.
        # But if the user wants to crack, they might not provide it.
        # The original code asked for key even in general case but allowed empty.
        key = input("Enter key (leave empty if you want to crack it): ").strip()
        if key:
            params['key'] = key
        return params

    def _get_input_text(self, prompt: str, initial_input: Optional[str] = None) -> Optional[str]:
        text = initial_input
        if text is None:
            text = input(f"{prompt} (or 'browse' for file): ").strip()
        
        if text.lower() == 'browse':
            selected = browse_file()
            if selected:
                text = selected
            else:
                return None
        
        if os.path.isfile(text):
            try:
                with open(text, 'r', encoding='utf-8') as f:
                    content = f.read()
                print(f"[*] Loaded {len(content)} characters from {text}")
                return content
            except Exception as e:
                print(f"[!] Error reading file: {e}")
                return None
        return text

    def encrypt_ui(self, cipher_instance) -> None:
        text = self._get_input_text("Enter text to encrypt")
        if not text:
             return
        try:
            result = cipher_instance.encrypt(text)
            print(f"\n[=] Encrypted Result: {result}")
        except Exception as e:
            print(f"[!] Encryption failed: {e}")

    def decrypt_ui(self, cipher_instance) -> None:
        text = self._get_input_text("Enter text to decrypt")
        if not text:
             return
        try:
            result = cipher_instance.decrypt(text)
            print(f"\n[=] Decrypted Result: {result}")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")

    def crack_ui(self, cipher_instance, initial_input: Optional[str] = None) -> None:
        text_input = self._get_input_text("Enter text/data to crack", initial_input)
        if not text_input:
             return
             
        if not isinstance(text_input, str):
             print("[!] Vigenere requires string input, not bytes.")
             return
        print("[*] Attempting to crack Vigenère cipher (checking English/Slovak profiles)...")
        try:
            result = cipher_instance.crack_cipher(text_input)
            print(f"\n[=] Crack Result:\n{result}")
        except Exception as e:
            print(f"[!] Cracking failed: {e}")
