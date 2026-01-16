import sys
import os
from typing import Dict, Callable, Optional, Any
from ciphers.cipher_factory import CipherFactory
from ciphers.base_cipher import BaseCipher
from handlers.handler_factory import HandlerFactory
from tools.ui_utils import browse_file

class CipherCLI:
    def __init__(self):
        self.current_cipher: Optional[BaseCipher] = None
        self.current_cipher_name: Optional[str] = None
        self.running = True
        self.menu_options: Dict[str, tuple[str, Callable]] = {
            '1': ('Select Cipher', self.select_cipher),
            '2': ('Encrypt', self.encrypt_action),
            '3': ('Decrypt', self.decrypt_action),
            '4': ('Crack', self.crack_action),
            '0': ('Exit', self.exit_app)
        }

    def get_menu_options(self) -> Dict[str, tuple[str, Callable]]:
        options = {
            '1': ('Select Cipher', self.select_cipher),
            '0': ('Exit', self.exit_app)
        }

        if self.current_cipher:
            options['2'] = ('Encrypt', self.encrypt_action)
            options['3'] = ('Decrypt', self.decrypt_action)
            
            if self.current_cipher_name:
                handler = HandlerFactory.get_handler(self.current_cipher_name)
                if handler.can_crack:
                    options['4'] = ('Crack / Analyze', self.crack_action)
            
        return options

    def run(self):
        print("=========================================")
        print("          Universal Cipher Tool          ")
        print("=========================================")

        while self.running:
            self.display_status()
            current_options = self.get_menu_options()
            self.display_menu(current_options)
            choice = input("\nSelect an option: ").strip()

            if choice in current_options:
                _, action = current_options[choice]
                try:
                    action()
                except Exception as e:
                    print(f"\n[!] Error during execution: {e}")
            else:
                print("\n[!] Invalid option, please try again.")

            print("-" * 40)

    def display_status(self):
        if self.current_cipher:
            name = self.current_cipher.__class__.__name__
            if name.endswith("Cipher"):
                cipher_name = name[:-6] + " Cipher"
            else:
                cipher_name = name
        else:
            cipher_name = "None"
        print(f"\n[Status] Current Cipher: {cipher_name}")

    def display_menu(self, options: Dict[str, tuple[str, Callable]]):
        print("\nMenu Options:")
        sorted_options = sorted(options.items(), key=lambda x: x[0])
        if sorted_options and sorted_options[0][0] == '0':
            sorted_options.append(sorted_options.pop(0))

        for key, (desc, _) in sorted_options:
            print(f"  {key}. {desc}")

    def exit_app(self):
        print("\nGoodbye!")
        self.running = False

    def select_cipher(self):
        available = CipherFactory.get_available_ciphers()
        print("\nAvailable Ciphers:")
        for i, name in enumerate(available, 1):
             print(f"  {i}. {name.capitalize()}")

        choice = input("\nEnter cipher number or name: ").lower().strip()
        
        cipher_name = None
        if choice.isdigit():
             idx = int(choice) - 1
             if 0 <= idx < len(available):
                 cipher_name = available[idx]
             else:
                 print(f"[!] Invalid selection number.")
                 return
        else:
             cipher_name = choice

        if cipher_name not in available:
            print(f"[!] Cipher '{choice}' not found.")
            return

        handler = HandlerFactory.get_handler(cipher_name)
        dummy_params = handler.get_default_params()

        try:
            self.current_cipher = CipherFactory.get_cipher(cipher_name, **dummy_params)
            self.current_cipher_name = cipher_name
            print(f"\n[+] Selected {cipher_name.capitalize()}. Parameters will be configured during action.")
        except Exception as e:
            print(f"[!] Failed to load cipher: {e}")

    def encrypt_action(self):
        if not self.current_cipher or not self.current_cipher_name:
            print("[!] No cipher selected.")
            return
        
        handler = HandlerFactory.get_handler(self.current_cipher_name)
        
        try:
             params = handler.get_config_params(intent='encrypt')
             self.current_cipher = CipherFactory.get_cipher(self.current_cipher_name, **params)
        except Exception as e:
             print(f"[!] Configuration failed: {e}")
             return

        try:
            handler.encrypt_ui(self.current_cipher)
        except Exception as e:
            print(f"[!] User Interface Error: {e}")

    def decrypt_action(self):
        if not self.current_cipher or not self.current_cipher_name:
            print("[!] No cipher selected.")
            return

        handler = HandlerFactory.get_handler(self.current_cipher_name)
        
        try:
             params = handler.get_config_params(intent='decrypt')
             self.current_cipher = CipherFactory.get_cipher(self.current_cipher_name, **params)
        except Exception as e:
             print(f"[!] Configuration failed: {e}")
             return
            
        try:
            handler.decrypt_ui(self.current_cipher)
        except Exception as e:
            print(f"[!] User Interface Error: {e}")

    def crack_action(self):
        if not self.current_cipher or not self.current_cipher_name:
            print("[!] No cipher selected.")
            return

        print(f"[*] Preparing to crack {self.current_cipher_name.capitalize()}...")
        
        handler = HandlerFactory.get_handler(self.current_cipher_name)
        handler.crack_ui(self.current_cipher, initial_input=None)

if __name__ == "__main__":
    try:
        app = CipherCLI()
        app.run()
    except KeyboardInterrupt:
        print("\n\nExiting...")
