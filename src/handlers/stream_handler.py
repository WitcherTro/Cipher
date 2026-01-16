import os
from typing import Dict, Any, Optional
from handlers.base_handler import BaseHandler
from tools.ui_utils import browse_file, save_file_dialog

class StreamHandler(BaseHandler):
    @property
    def can_crack(self) -> bool:
        return True

    def get_default_params(self) -> Dict[str, Any]:
        return {"password": "dummy"}

    def get_config_params(self, intent: str = "general") -> Dict[str, Any]:
        params = {}
        password = input("Enter password: ").strip()
        if not password:
             print("[!] Warning: Password is empty. Stream cipher might fail.")
        params['password'] = password
        return params

    def encrypt_ui(self, cipher_instance) -> None:
        text = input("Enter text to encrypt (or 'browse' for file): ").strip()
        if text.lower() == 'browse':
            selected = browse_file()
            if selected:
                text = selected
        
        # Check file
        data_input = text
        if os.path.isfile(text):
            try:
                with open(text, 'rb') as f:
                    data_input = f.read()
                print(f"[*] Loaded {len(data_input)} bytes.")
            except Exception as e:
                print(f"[!] Error reading file: {e}")
                return
        
        try:
            result = cipher_instance.encrypt(data_input)
            # result type: str | bytes
            
            # Check if result is bytes
            if isinstance(result, bytes):
                print(f"[=] Encrypted {len(result)} bytes.")
                save_path = input("Enter output filename (or 'browse' for GUI, Enter to view hex): ").strip()
                if save_path.lower() == 'browse':
                     path = save_file_dialog()
                     if path:
                         save_path = path

                if save_path:
                    with open(save_path, 'wb') as f:
                        f.write(result)
                    print(f"[+] Saved to {save_path}")
                else:
                    print(f"[=] Hex Result: {result.hex()}")
            else:
                # result is str
                print(f"\n[=] Encrypted Result: {result}")

        except Exception as e:
            print(f"[!] Encryption failed: {e}")

    def decrypt_ui(self, cipher_instance) -> None:
         text_input = input("Enter hex/text to decrypt (or 'browse' for file): ").strip()
         if text_input.lower() == 'browse':
              selected = browse_file()
              if selected:
                   text_input = selected

         data_input = text_input
         if os.path.isfile(text_input):
              try:
                   with open(text_input, 'rb') as f:
                        data_input = f.read()
                   print(f"[*] Loaded {len(data_input)} bytes.")
              except Exception as e:
                   print(f"[!] File error: {e}")
                   return
         
         try:
             result = cipher_instance.decrypt(data_input)
             # result type: str | bytes

             if isinstance(result, bytes):
                 save_path = input("Enter output filename (or 'browse' for GUI, Enter to view text): ").strip()
                 if save_path.lower() == 'browse':
                      path = save_file_dialog()
                      if path:
                          save_path = path

                 if save_path:
                      with open(save_path, 'wb') as f:
                           f.write(result)
                      print(f"[+] Saved to {save_path}")
                 else:
                      try:
                           print(f"\n[=] Decrypted Text: {result.decode('utf-8')}")
                      except:
                           print(f"\n[=] Decrypted (Hex): {result.hex()}")
             else:
                 # result is str
                 print(f"\n[=] Decrypted Result: {result}")
                 
         except Exception as e:
             print(f"[!] Decryption failed: {e}")

    def crack_ui(self, cipher_instance, initial_input: Optional[str] = None) -> None:
        print("(For Stream Cipher, you can provide a file path or type 'browse' for GUI)")
        
        if initial_input is None:
             initial_input = input("Enter text/data/filepath to crack: ").strip()
             if initial_input.lower() == 'browse':
                  selected = browse_file()
                  if selected:
                       initial_input = selected
        
        text_input = initial_input
        # Stream Cipher logic often deals with binary files. 
        # main.py had logic to check if text_input is a path or starts with "file:"
        
        data_to_crack = text_input

        # Check for file input logic specific to Stream Cipher
        path = None
        if isinstance(text_input, str):
            if os.path.isfile(text_input):
                path = text_input
            elif text_input.startswith("file:"):
                potential_path = text_input.split("file:", 1)[1]
                if os.path.isfile(potential_path):
                    path = potential_path

        if path:
            try:
                with open(path, 'rb') as f:
                    data_to_crack = f.read()
                print(f"[*] Loaded binary data from {path}")
            except Exception as e:
                print(f"[!] Error reading file: {e}")
                return
        
        print("[*] Brute-forcing Stream Cipher (PIN 100000-999999)...")
        try:
             result = cipher_instance.crack_cipher(data_to_crack)
             print(f"\n{result}")
        except Exception as e:
             print(f"[!] Crack failed: {e}")

