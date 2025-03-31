import hashlib
import os

def calculate_hash(file_path, algorithm='sha256'):
    """Calculates the hash of a given file using the specified algorithm."""
    hash_func = getattr(hashlib, algorithm, None)
    if not hash_func:
        print(f"[!] Unsupported hashing algorithm: {algorithm}")
        return None
    
    try:
        with open(file_path, 'rb') as f:
            hasher = hash_func()
            while chunk := f.read(4096):
                hasher.update(chunk)
            return hasher.hexdigest()
    except FileNotFoundError:
        print("[!] File not found.")
        return None

def main():
    print("\n[+] Hash Calculator")
    file_path = input("Enter the file path: ").strip()
    if not os.path.exists(file_path):
        print("[!] Invalid file path.")
        return
    
    print("\nSelect hashing algorithm:")
    print("1. MD5")
    print("2. SHA-1")
    print("3. SHA-256 (default)")
    print("4. SHA-512")
    
    choice = input("Enter choice (1-4): ").strip()
    algorithms = {'1': 'md5', '2': 'sha1', '3': 'sha256', '4': 'sha512'}
    algorithm = algorithms.get(choice, 'sha256')
    
    file_hash = calculate_hash(file_path, algorithm)
    if file_hash:
        print(f"\n[+] {algorithm.upper()} Hash: {file_hash}")
        
        verify = input("Do you want to compare with an existing hash? (y/n): ").strip().lower()
        if verify == 'y':
            reference_hash = input("Enter the reference hash: ").strip()
            if file_hash == reference_hash:
                print("[✔] Hash match! File integrity verified.")
            else:
                print("[✖] Hash mismatch! File may be altered.")

if __name__ == "__main__":
    main()
