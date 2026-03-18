"""
AES Encryptor module.

This module provides AES-256-GCM encryption and decryption functionality
with PBKDF2 key derivation for password-based encryption.

Security Features:
- AES-256-GCM for authenticated encryption
- PBKDF2-HMAC-SHA256 with 100,000 iterations for key derivation
- Random salt for each encryption
- Random IV/nonce for each encryption
- Authentication tag verification
"""

import os
import secrets
from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from .base import BaseEncryptor
from ..constants import (
    AES_KEY_SIZE,
    AES_IV_SIZE,
    AES_TAG_SIZE,
    PBKDF2_SALT_SIZE,
    PBKDF2_ITERATIONS,
    FILE_MAGIC,
    FILE_VERSION,
    ERROR_INVALID_PASSWORD,
    ERROR_INVALID_FILE,
)


class AESEncryptor(BaseEncryptor):
    """
    AES-256-GCM file encryptor with PBKDF2 key derivation.

    This class provides secure file encryption using AES-256-GCM with
    password-based key derivation using PBKDF2-HMAC-SHA256.

    File Format:
        [MAGIC (4 bytes)]
        [VERSION (2 bytes)]
        [SALT (16 bytes)]
        [IV (12 bytes)]
        [CIPHERTEXT with TAG]

    Example:
        >>> encryptor = AESEncryptor()
        >>> encryptor.encrypt_file("secret.txt", "secret.enc", "mypassword")
        True
        >>> encryptor.decrypt_file("secret.enc", "secret_decrypted.txt", "mypassword")
        True
    """

    def __init__(self, iterations: int = PBKDF2_ITERATIONS):
        """
        Initialize the AES encryptor.

        Args:
            iterations: Number of PBKDF2 iterations (default: 100000).
        """
        self.iterations = iterations

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive an encryption key from a password using PBKDF2.

        Args:
            password: The password to derive the key from.
            salt: Random salt for key derivation.

        Returns:
            Derived 256-bit key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        password: str,
        overwrite: bool = False,
    ) -> bool:
        """
        Encrypt a file using AES-256-GCM.

        Args:
            input_path: Path to the file to encrypt.
            output_path: Path to save the encrypted file.
            password: Password for encryption.
            overwrite: Whether to overwrite existing output file.

        Returns:
            True if encryption was successful.

        Raises:
            FileNotFoundError: If input file does not exist.
            ValueError: If password is empty.
            FileExistsError: If output file exists and overwrite is False.

        Example:
            >>> encryptor = AESEncryptor()
            >>> encryptor.encrypt_file("document.pdf", "document.enc", "secret123")
            True
        """
        input_path = Path(input_path)
        output_path = Path(output_path)

        # Validate inputs
        self._validate_input_file(input_path)
        self._validate_output_file(output_path, overwrite)
        self._validate_password(password)

        # Generate random salt and IV
        salt = secrets.token_bytes(PBKDF2_SALT_SIZE)
        iv = secrets.token_bytes(AES_IV_SIZE)

        # Derive key from password
        key = self._derive_key(password, salt)

        # Read plaintext
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        # Encrypt using AES-GCM
        aesgcm = AESGCM(key)
        # AES-GCM appends the tag to the ciphertext
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)

        # Write encrypted file with header
        with open(output_path, 'wb') as f:
            f.write(FILE_MAGIC)          # 4 bytes
            f.write(FILE_VERSION)        # 2 bytes
            f.write(salt)                # 16 bytes
            f.write(iv)                  # 12 bytes
            f.write(ciphertext_with_tag) # ciphertext + 16 byte tag

        # Securely clear the key from memory
        self._secure_clear(key)

        return True

    def decrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        password: str,
        overwrite: bool = False,
    ) -> bool:
        """
        Decrypt a file that was encrypted with AES-256-GCM.

        Args:
            input_path: Path to the encrypted file.
            output_path: Path to save the decrypted file.
            password: Password used for encryption.
            overwrite: Whether to overwrite existing output file.

        Returns:
            True if decryption was successful.

        Raises:
            FileNotFoundError: If input file does not exist.
            ValueError: If password is empty or file is invalid.
            InvalidPasswordError: If password is incorrect.

        Example:
            >>> encryptor = AESEncryptor()
            >>> encryptor.decrypt_file("document.enc", "document.pdf", "secret123")
            True
        """
        input_path = Path(input_path)
        output_path = Path(output_path)

        # Validate inputs
        self._validate_input_file(input_path)
        self._validate_output_file(output_path, overwrite)
        self._validate_password(password)

        # Read encrypted file
        with open(input_path, 'rb') as f:
            # Read header
            magic = f.read(4)
            version = f.read(2)
            salt = f.read(PBKDF2_SALT_SIZE)
            iv = f.read(AES_IV_SIZE)
            ciphertext_with_tag = f.read()

        # Validate file format
        if magic != FILE_MAGIC:
            raise ValueError(ERROR_INVALID_FILE)
        if len(salt) != PBKDF2_SALT_SIZE:
            raise ValueError(ERROR_INVALID_FILE)
        if len(iv) != AES_IV_SIZE:
            raise ValueError(ERROR_INVALID_FILE)

        # Derive key from password
        key = self._derive_key(password, salt)

        try:
            # Decrypt using AES-GCM
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)

            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(plaintext)

            return True

        except Exception:
            # Invalid password or corrupted data
            raise ValueError(ERROR_INVALID_PASSWORD)

        finally:
            # Securely clear the key from memory
            self._secure_clear(key)

    def encrypt_data(self, data: bytes, password: str) -> bytes:
        """
        Encrypt bytes data using AES-256-GCM.

        Args:
            data: Data to encrypt.
            password: Password for encryption.

        Returns:
            Encrypted data with header.
        """
        self._validate_password(password)

        # Generate random salt and IV
        salt = secrets.token_bytes(PBKDF2_SALT_SIZE)
        iv = secrets.token_bytes(AES_IV_SIZE)

        # Derive key from password
        key = self._derive_key(password, salt)

        # Encrypt
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(iv, data, None)

        # Build output: header + ciphertext
        result = FILE_MAGIC + FILE_VERSION + salt + iv + ciphertext_with_tag

        # Securely clear the key
        self._secure_clear(key)

        return result

    def decrypt_data(self, data: bytes, password: str) -> bytes:
        """
        Decrypt bytes data that was encrypted with AES-256-GCM.

        Args:
            data: Encrypted data with header.
            password: Password used for encryption.

        Returns:
            Decrypted data.
        """
        self._validate_password(password)

        # Parse header
        if len(data) < 4 + 2 + PBKDF2_SALT_SIZE + AES_IV_SIZE + AES_TAG_SIZE:
            raise ValueError(ERROR_INVALID_FILE)

        magic = data[0:4]
        version = data[4:6]
        salt = data[6:6 + PBKDF2_SALT_SIZE]
        iv = data[6 + PBKDF2_SALT_SIZE:6 + PBKDF2_SALT_SIZE + AES_IV_SIZE]
        ciphertext_with_tag = data[6 + PBKDF2_SALT_SIZE + AES_IV_SIZE:]

        if magic != FILE_MAGIC:
            raise ValueError(ERROR_INVALID_FILE)

        # Derive key
        key = self._derive_key(password, salt)

        try:
            # Decrypt
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
            return plaintext
        except Exception:
            raise ValueError(ERROR_INVALID_PASSWORD)
        finally:
            self._secure_clear(key)

    @staticmethod
    def _secure_clear(data: bytes) -> None:
        """
        Attempt to securely clear bytes from memory.

        Note: In Python, this is not guaranteed due to string interning
        and garbage collection, but it's a best-effort approach.
        """
        # Python doesn't have direct memory access, but we can try
        # In production, consider using memoryview or secure memory libraries
        pass

    @staticmethod
    def is_encrypted_file(path: Union[str, Path]) -> bool:
        """
        Check if a file is encrypted with this encryptor.

        Args:
            path: Path to the file to check.

        Returns:
            True if the file appears to be encrypted.
        """
        path = Path(path)
        if not path.exists() or not path.is_file():
            return False

        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                return magic == FILE_MAGIC
        except Exception:
            return False
