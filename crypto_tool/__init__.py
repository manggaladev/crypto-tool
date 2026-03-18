"""
crypto-tool - A file encryptor/decryptor using AES-256-GCM and RSA.

This package provides secure file encryption using modern cryptographic
algorithms with both CLI and programmatic interfaces.

Security Features:
- AES-256-GCM for authenticated encryption
- PBKDF2-HMAC-SHA256 with 100,000 iterations for key derivation
- RSA-OAEP for hybrid encryption
- Random salt and IV for each encryption

Example:
    >>> from crypto_tool import AESEncryptor
    >>> encryptor = AESEncryptor()
    >>> encryptor.encrypt_file("secret.txt", "secret.enc", "mypassword")
    True
    >>> encryptor.decrypt_file("secret.enc", "secret.txt", "mypassword")
    True
"""

from .encryptors import (
    BaseEncryptor,
    AESEncryptor,
    RSAEncryptor,
    generate_key_pair,
)

from .constants import (
    AES_KEY_SIZE,
    AES_IV_SIZE,
    AES_TAG_SIZE,
    PBKDF2_SALT_SIZE,
    PBKDF2_ITERATIONS,
    RSA_KEY_SIZE,
    FILE_MAGIC,
    ENCRYPTED_EXT,
)

__version__ = "1.0.0"
__author__ = "manggaladev"
__all__ = [
    'AESEncryptor',
    'RSAEncryptor',
    'BaseEncryptor',
    'generate_key_pair',
    'AES_KEY_SIZE',
    'AES_IV_SIZE',
    'AES_TAG_SIZE',
    'PBKDF2_SALT_SIZE',
    'PBKDF2_ITERATIONS',
    'RSA_KEY_SIZE',
    'FILE_MAGIC',
    'ENCRYPTED_EXT',
]
