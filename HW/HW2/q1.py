import glob
import json
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def run_aes(mode : str, plaintext : bytes) -> None:
    # Pad plaintext        
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    key = os.urandom(16)

    
    if (mode == "CBC"):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct_cbc = encryptor.update(padded_plaintext) + encryptor.finalize()
        decryptor = cipher.decryptor()
        decrypted_cbc = decryptor.update(ct_cbc) + decryptor.finalize()
        
        # Remove padding from decrypted data
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_cbc = unpadder.update(decrypted_cbc) + unpadder.finalize()
        
        print_encryption_details("CBC", key, iv, plaintext, ct_cbc, decrypted_cbc)
        
    elif (mode == "ECB"):
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        ct_ecb = encryptor.update(padded_plaintext) + encryptor.finalize()
        decryptor = cipher.decryptor()
        decrypted_ecb = decryptor.update(ct_ecb) + decryptor.finalize()
    
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_ecb = unpadder.update(decrypted_ecb) + unpadder.finalize()
        
        print_encryption_details("ECB", key, None, plaintext, ct_ecb, decrypted_ecb)
        


def print_encryption_details(mode, key, iv, plaintext, ciphertext, decrypted):
    print(f"\n{'='*20} {mode} REPORT {'='*20}")
    print(f"Key (Hex):")
    print(f"  {key.hex()}")
    
    if iv:
        print(f"IV (Hex):")
        print(f"  {iv.hex()}")
    else:
        print(f"IV:              None (Not used in this mode)")
    
    print("-" * 60)

    try:
        plaintext_str = plaintext.decode('utf-8')
    except (AttributeError, UnicodeDecodeError): 
        plaintext_str = str(plaintext)
    
    print(f"Original Text:")
    print(f"  {plaintext_str}")

    print(f"Ciphertext (Hex):")
    print(f"  {ciphertext.hex()}")

    try:
        decrypted_str = decrypted.decode('utf-8')
    except (AttributeError, UnicodeDecodeError):
        decrypted_str = str(decrypted)
    
    print(f"Decrypted Text:")
    print(f"  {decrypted_str}")
        
    print("="*60 + "\n")


def create_plaintext_from_json() -> str:
        json_paths = glob.glob("./**/secrets.json", recursive=True)
        
        # Handle case where file is not found
        if not json_paths:
            print("Error: 'secrets.json' not found.")
            raise FileNotFoundError

        json_file_path = json_paths[0]

        with open(json_file_path, 'r') as f:
            json_content = json.load(f) 
            
        # Check if the expected key exists and it's a list
        if not isinstance(json_content, dict) or "students" not in json_content or not isinstance(json_content["students"], list):
            print("Error: JSON structure is unexpected. Expected an object with a 'students' list.")
            raise ValueError

        students = json_content["students"]

        student_1 = students[0]
        student_2 = students[1]
        
        # Access the name and ID keys directly from the student objects.
        plaintext = (
            f"Homework 2 for the Course Cryptology: "
            f"Student 1 {student_1.get('name')}, "
            f"{student_1.get('id')} and "
            f"Student 2 {student_2.get('name')}, "
            f"ID: {student_2.get('id')}."
        )
        
        return plaintext


def main():
    try:
        plaintext = create_plaintext_from_json().encode('utf-8')

        run_aes(mode="CBC", plaintext=plaintext)
        run_aes(mode="ECB", plaintext=plaintext)
    
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON file: {e}")
    except KeyError as e:
        print(f"Error accessing key in student data: {e}. Check if 'name' or 'id' keys exist.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()