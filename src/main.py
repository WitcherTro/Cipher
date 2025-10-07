from tools.text_utils import is_valid_input
from ciphers.cipher_factory import CipherFactory

def main():
    print("Welcome to the Cipher Tool!")
    current_cipher = None
    
    while True:
        print("\nMain Menu:")
        if current_cipher:
            print(f"Current cipher: {current_cipher.__class__.__name__}")
        else:
            print("No cipher selected")
            
        print("1. Select cipher")
        print("2. Encrypt text")
        print("3. Decrypt text (known key)")
        print("4. Crack encrypted text") 
        print("5. Change language")
        print("6. Show all possible decryptions")
        print("7. Exit")
        
        choice = input("\nEnter your choice (1-7): ")
        
        if choice == "7":
            break
            
        if choice == "1":
            print("\nAvailable ciphers:", ", ".join(CipherFactory.get_available_ciphers()))
            cipher_name = input("Enter cipher name: ").lower()
            try:
                current_cipher = CipherFactory.get_cipher(cipher_name)
                print(f"Selected cipher: {cipher_name}")
            except ValueError as e:
                print(f"Error: {e}")
            continue

        if not current_cipher:
            print("Error: Please select a cipher first")
            continue
            
        if choice == "5":
            print("\nAvailable languages:", ", ".join(current_cipher.analyzer.get_supported_languages()))
            language = input("Enter language name: ").lower()
            try:
                current_cipher.set_language(language)
                print(f"Language set to {language}")
            except ValueError as e:
                print(f"Error: {e}")
            continue
            
        text = input("Enter text: ")
        if not is_valid_input(text):
            print("Error: Text should contain only letters")
            continue
            
        if choice == "2":
            shift = int(input("Enter shift (default 3): ") or 3)
            current_cipher.shift = shift
            result = current_cipher.encrypt(text)
            print(f"Encrypted text: {result}")
            
        elif choice == "3":
            shift = int(input("Enter shift (default 3): ") or 3)
            current_cipher.shift = shift
            result = current_cipher.decrypt(text, known_shift=True)
            print(f"Decrypted text: {result}")
            
        elif choice == "4":
            result = current_cipher.decrypt(text, known_shift=False)
            print(f"Cracked text: {result}")
            if isinstance(current_cipher, CipherFactory.get_cipher("caesar").__class__):
                print(f"Found shift: {current_cipher.shift}")
                
        elif choice == "6":
            if isinstance(current_cipher, CipherFactory.get_cipher("caesar").__class__):
                results = current_cipher.bruteforce(text)
                print("\nAll possible decryptions:")
                for shift, decrypted in results:
                    print(f"Shift {shift:2d}: {decrypted}")
            else:
                print("Bruteforce not available for this cipher")
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()