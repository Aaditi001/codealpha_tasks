import os
import argparse
from cryptography.fernet import Fernet

def read_file(filename):
    try:
        with open(filename, 'r') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def write_file(filename, data):
    try:
        with open(filename, 'w') as f:
            f.write(data)
    except Exception as e:
        print(f"Error writing file: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Enter a filename")
    args = parser.parse_args()
    filename = args.filename

    # Validate filename
    if not filename.endswith(".txt"):
        print("Invalid filename")
        return

    # Check file permissions
    if not os.access(filename, os.R_OK):
        print("Permission denied")
        return

    # Read file
    data = read_file(filename)
    if data:
        print(data)

    # Encrypt data
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())

    # Write encrypted data
    write_file(filename, encrypted_data.decode())

if __name__ == "__main__":
    main()
