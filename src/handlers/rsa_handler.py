from typing import Dict, Any, Optional
from handlers.base_handler import BaseHandler

class RSAHandler(BaseHandler):
    @property
    def can_crack(self) -> bool:
        return True

    def get_default_params(self) -> Dict[str, Any]:
        return {"n": 3233}

    def get_config_params(self, intent: str = "general") -> Dict[str, Any]:
        params = {}
        print("RSA Configuration")
        n_val = input("Modulus (n) [Leave empty for default 3233]: ").strip()
        
        if n_val:
            params['n'] = int(n_val)
            e_val = input("Public Exponent (e) [default 65537]: ").strip()
            params['e'] = int(e_val) if e_val else 65537
            
            # Only ask for private key 'd' if the intent is explicitly Decryption
            if intent == 'decrypt':
                d_val = input("Private Exponent (d): ").strip()
                if d_val:
                    params['d'] = int(d_val)
                else:
                    print("[!] Warning: No private key provided. Decryption will likely fail.")
        else:
            print("[*] Using default example RSA keys.")
            params['n'] = 3233
            params['e'] = 17
            params['d'] = 2753
        return params

    def crack_ui(self, cipher_instance, initial_input: Optional[str] = None) -> None:
        print("\nConfiguring RSA for Cracking:")
        n_str = input("Enter modulus n: ").strip()
        e_str = input("Enter public exponent e [65537]: ").strip()
        
        if n_str: 
            cipher_instance.n = int(n_str)
        if e_str: 
            cipher_instance.e = int(e_str)

        print(f"[*] Cracking RSA (n={cipher_instance.n})...")
        
        y_val: int
        if initial_input and initial_input.isdigit():
             y_val = int(initial_input)
        else:
             print("(For RSA, please enter the ciphertext integer 'y')")
             y_input = input("Enter ciphertext integer y: ").strip()
             try:
                 y_val = int(y_input)
             except ValueError:
                 print("[!] Error: Ciphertext must be an integer for RSA cracking.")
                 return

        try:
            m = cipher_instance.crack(y_val)
            print(f"\n[=] Crack Result (Decrypted Integer): {m}")
        except Exception as e:
            print(f"[!] Crack failed: {e}")
