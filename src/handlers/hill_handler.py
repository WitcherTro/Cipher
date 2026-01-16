import numpy as np
from typing import Dict, Any, Optional
from handlers.base_handler import BaseHandler

class HillHandler(BaseHandler):
    @property
    def can_crack(self) -> bool:
        return True

    def get_config_params(self, intent: str = "general") -> Dict[str, Any]:
        params = {}
        print("Enter key matrix (space-separated integers). Example for 2x2: '1 2 3 4'")
        print("Leave empty if you intend to crack the cipher using a known plaintext (crib).")
        raw_nums = input("Matrix: ").strip().split()
        if raw_nums:
            try:
                nums = [int(x) for x in raw_nums]
                size = int(len(nums) ** 0.5)
                if size * size != len(nums):
                     raise ValueError("Key matrix must be square (e.g., 4, 9, 16 numbers).")
                params['key_matrix'] = np.array(nums).reshape(size, size).tolist()
            except Exception as e:
                print(f"[!] Invalid matrix input: {e}")
                # We might want to re-raise or return empty params? 
                # Original code raised ValueError which was caught in main loop probably or crashed
                # main.py didn't have specific try/except around _collect_cipher_params, so it would crash/print error in main loop.
                raise e
        else:
            params['key_matrix'] = None
        return params

    def crack_ui(self, cipher_instance, initial_input: Optional[str] = None) -> None:
        if not initial_input:
             initial_input = input("Enter text/data to crack: ").strip()

        # Handle type conversion
        text_input = initial_input
        if not isinstance(text_input, str):
            try:
                if isinstance(text_input, bytes):
                    text_input = text_input.decode()
                elif hasattr(text_input, 'tobytes'): # memoryview/bytearray
                    text_input = bytes(text_input).decode()
                else:
                    print("[!] Hill requires string input.")
                    return
            except: 
                print("[!] Hill requires string input.")
                return
        
        crib = input("Enter known plaintext (crib) - length must be square (4, 9, 16...): ").strip()
        if not crib:
            print("[!] Crib is required for Hill cracking.")
            return
            
        try:
            result = cipher_instance.crack_cipher(text_input, crib)
            print(f"\n[=] Crack Result:\n{result}")
        except Exception as e:
            print(f"[!] Cracking failed: {e}")
