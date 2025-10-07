from ciphers.cipher_utils import is_valid_input
from ciphers.caesar_cipher import CaesarCipher

def main():
    print("Welcome to the Cipher!")
    caesar = CaesarCipher()
    
    while True:
        print("\nOptions:")
        print("1. Encrypt text")
        print("2. Decrypt text")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == "3":
            break
            
        text = input("Enter text: ")
        if not is_valid_input(text):
            print("Error: Text should contain only letters")
            continue
            
        if choice == "1":
            result = caesar.encrypt(text)
            print(f"Encrypted text: {result}")
        elif choice == "2":
            result = caesar.decrypt(text)
            print(f"Decrypted text: {result}")
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()