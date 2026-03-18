"""
Basic usage examples for crypto-tool.

This script demonstrates how to use the crypto-tool library
for file encryption and decryption.
"""

from pathlib import Path
from crypto_tool import AESEncryptor, RSAEncryptor, generate_key_pair


def aes_example():
    """Example: AES encryption with password."""
    print("=== AES Encryption Example ===")

    # Create encryptor
    encryptor = AESEncryptor()

    # Create a test file
    test_file = Path("example.txt")
    test_file.write_text("This is a secret message!")

    encrypted_file = Path("example.enc")
    decrypted_file = Path("example_decrypted.txt")

    # Encrypt
    encryptor.encrypt_file(test_file, encrypted_file, "mypassword")
    print(f"Encrypted: {test_file} -> {encrypted_file}")

    # Decrypt
    encryptor.decrypt_file(encrypted_file, decrypted_file, "mypassword")
    print(f"Decrypted: {encrypted_file} -> {decrypted_file}")

    # Verify
    print(f"Original: {test_file.read_text()}")
    print(f"Decrypted: {decrypted_file.read_text()}")

    # Cleanup
    test_file.unlink()
    encrypted_file.unlink()
    decrypted_file.unlink()


def rsa_example():
    """Example: RSA encryption with key pair."""
    print("\n=== RSA Encryption Example ===")

    # Create encryptor
    encryptor = RSAEncryptor()

    # Generate key pair
    private_key, public_key = encryptor.generate_key_pair()

    # Save keys
    private_path = Path("private.pem")
    public_path = Path("public.pem")

    encryptor.save_private_key(private_key, private_path, password="keypass")
    encryptor.save_public_key(public_key, public_path)
    print(f"Generated keys: {private_path}, {public_path}")

    # Create test file
    test_file = Path("rsa_example.txt")
    test_file.write_text("Confidential data!")

    encrypted_file = Path("rsa_example.enc")
    decrypted_file = Path("rsa_example_decrypted.txt")

    # Encrypt with public key
    encryptor.encrypt_file(test_file, encrypted_file, public_key_path=public_path)
    print(f"Encrypted: {test_file} -> {encrypted_file}")

    # Decrypt with private key
    encryptor.decrypt_file(
        encrypted_file, decrypted_file,
        private_key_path=private_path,
        key_password="keypass"
    )
    print(f"Decrypted: {encrypted_file} -> {decrypted_file}")

    # Verify
    print(f"Original: {test_file.read_text()}")
    print(f"Decrypted: {decrypted_file.read_text()}")

    # Cleanup
    test_file.unlink()
    encrypted_file.unlink()
    decrypted_file.unlink()
    private_path.unlink()
    public_path.unlink()


def data_encryption_example():
    """Example: Encrypt data in memory."""
    print("\n=== Data Encryption Example ===")

    encryptor = AESEncryptor()

    # Encrypt data
    original_data = b"Sensitive information that needs protection"
    encrypted = encryptor.encrypt_data(original_data, "secret123")
    print(f"Original size: {len(original_data)} bytes")
    print(f"Encrypted size: {len(encrypted)} bytes")

    # Decrypt data
    decrypted = encryptor.decrypt_data(encrypted, "secret123")
    print(f"Decrypted: {decrypted.decode()}")

    assert original_data == decrypted
    print("✓ Encryption/decryption successful!")


if __name__ == "__main__":
    aes_example()
    rsa_example()
    data_encryption_example()
