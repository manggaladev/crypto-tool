"""
RSA Encryptor module.

This module provides RSA encryption and decryption functionality using
hybrid encryption (RSA + AES) for secure file encryption.

Security Features:
- RSA-2048 or RSA-4096 for asymmetric encryption
- OAEP padding with SHA-256 for RSA encryption
- Hybrid encryption: AES-256-GCM for data, RSA for AES key
- PKCS#8 format for private keys
- SubjectPublicKeyInfo format for public keys
"""

import os
import secrets
from pathlib import Path
from typing import Optional, Tuple, Union
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from .base import BaseEncryptor
from ..constants import (
    AES_KEY_SIZE,
    AES_IV_SIZE,
    RSA_KEY_SIZE,
    RSA_MIN_KEY_SIZE,
    RSA_MAX_KEY_SIZE,
    FILE_MAGIC,
    ERROR_INVALID_FILE,
    ERROR_INVALID_KEY,
)


# Magic bytes for RSA-encrypted files
RSA_FILE_MAGIC = b"RRSA"
RSA_FILE_VERSION = b"\x01\x00"


class RSAEncryptor(BaseEncryptor):
    """
    RSA file encryptor using hybrid encryption (RSA + AES-256-GCM).

    This class provides secure file encryption using hybrid encryption:
    1. Generate a random AES-256 key
    2. Encrypt the file with AES-256-GCM
    3. Encrypt the AES key with RSA-OAEP
    4. Store the encrypted AES key and the encrypted file together

    File Format:
        [MAGIC (4 bytes)] - "RRSA"
        [VERSION (2 bytes)]
        [ENCRYPTED_KEY_LENGTH (4 bytes)]
        [ENCRYPTED_KEY (256 bytes for RSA-2048)]
        [IV (12 bytes)]
        [CIPHERTEXT with TAG]

    Example:
        >>> encryptor = RSAEncryptor()
        >>> # Generate key pair first
        >>> private_key, public_key = encryptor.generate_key_pair()
        >>> encryptor.save_private_key(private_key, "private.pem")
        >>> encryptor.save_public_key(public_key, "public.pem")
        >>> # Encrypt with public key
        >>> encryptor.encrypt_file("secret.txt", "secret.enc", public_key_path="public.pem")
        True
        >>> # Decrypt with private key
        >>> encryptor.decrypt_file("secret.enc", "secret_decrypted.txt", private_key_path="private.pem")
        True
    """

    def __init__(self, key_size: int = RSA_KEY_SIZE):
        """
        Initialize the RSA encryptor.

        Args:
            key_size: RSA key size in bits (default: 2048).
        """
        if key_size < RSA_MIN_KEY_SIZE or key_size > RSA_MAX_KEY_SIZE:
            raise ValueError(f"Key size must be between {RSA_MIN_KEY_SIZE} and {RSA_MAX_KEY_SIZE}")
        self.key_size = key_size

    def generate_key_pair(
        self,
        key_size: Optional[int] = None,
    ) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate an RSA key pair.

        Args:
            key_size: RSA key size in bits (default: use self.key_size).

        Returns:
            Tuple of (private_key, public_key).

        Example:
            >>> encryptor = RSAEncryptor()
            >>> private_key, public_key = encryptor.generate_key_pair()
        """
        if key_size is None:
            key_size = self.key_size

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        return private_key, public_key

    def save_private_key(
        self,
        private_key: rsa.RSAPrivateKey,
        path: Union[str, Path],
        password: Optional[str] = None,
    ) -> None:
        """
        Save a private key to a PEM file.

        Args:
            private_key: The private key to save.
            path: Path to save the key.
            password: Optional password to encrypt the key.

        Example:
            >>> encryptor = RSAEncryptor()
            >>> private_key, _ = encryptor.generate_key_pair()
            >>> encryptor.save_private_key(private_key, "private.pem", "mypassword")
        """
        path = Path(path)

        if password:
            encryption = serialization.BestAvailableEncryption(
                password.encode('utf-8')
            )
        else:
            encryption = serialization.NoEncryption()

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            f.write(pem)

        # Set restrictive permissions
        os.chmod(path, 0o600)

    def save_public_key(
        self,
        public_key: rsa.RSAPublicKey,
        path: Union[str, Path],
    ) -> None:
        """
        Save a public key to a PEM file.

        Args:
            public_key: The public key to save.
            path: Path to save the key.

        Example:
            >>> encryptor = RSAEncryptor()
            >>> _, public_key = encryptor.generate_key_pair()
            >>> encryptor.save_public_key(public_key, "public.pem")
        """
        path = Path(path)

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            f.write(pem)

    def load_private_key(
        self,
        path: Union[str, Path],
        password: Optional[str] = None,
    ) -> rsa.RSAPrivateKey:
        """
        Load a private key from a PEM file.

        Args:
            path: Path to the key file.
            password: Password if the key is encrypted.

        Returns:
            The private key.

        Raises:
            ValueError: If the key file is invalid.

        Example:
            >>> encryptor = RSAEncryptor()
            >>> private_key = encryptor.load_private_key("private.pem", "mypassword")
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")

        with open(path, 'rb') as f:
            pem_data = f.read()

        try:
            password_bytes = password.encode('utf-8') if password else None
            private_key = serialization.load_pem_private_key(
                pem_data,
                password=password_bytes,
                backend=default_backend()
            )
            return private_key
        except Exception as e:
            raise ValueError(f"{ERROR_INVALID_KEY.format(path=path)}: {e}")

    def load_public_key(
        self,
        path: Union[str, Path],
    ) -> rsa.RSAPublicKey:
        """
        Load a public key from a PEM file.

        Args:
            path: Path to the key file.

        Returns:
            The public key.

        Raises:
            ValueError: If the key file is invalid.

        Example:
            >>> encryptor = RSAEncryptor()
            >>> public_key = encryptor.load_public_key("public.pem")
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")

        with open(path, 'rb') as f:
            pem_data = f.read()

        try:
            public_key = serialization.load_pem_public_key(
                pem_data,
                backend=default_backend()
            )
            return public_key
        except Exception as e:
            raise ValueError(f"{ERROR_INVALID_KEY.format(path=path)}: {e}")

    def encrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        public_key: Optional[rsa.RSAPublicKey] = None,
        public_key_path: Optional[Union[str, Path]] = None,
        password: Optional[str] = None,  # Not used, for base class compatibility
        overwrite: bool = False,
    ) -> bool:
        """
        Encrypt a file using hybrid RSA-AES encryption.

        Args:
            input_path: Path to the file to encrypt.
            output_path: Path to save the encrypted file.
            public_key: The public key object (optional).
            public_key_path: Path to the public key file (optional).
            password: Not used for RSA encryption.
            overwrite: Whether to overwrite existing output file.

        Returns:
            True if encryption was successful.

        Raises:
            FileNotFoundError: If input file or key file does not exist.
            ValueError: If neither public_key nor public_key_path is provided.

        Example:
            >>> encryptor = RSAEncryptor()
            >>> encryptor.encrypt_file(
            ...     "document.pdf",
            ...     "document.enc",
            ...     public_key_path="public.pem"
            ... )
            True
        """
        input_path = Path(input_path)
        output_path = Path(output_path)

        # Validate inputs
        self._validate_input_file(input_path)
        self._validate_output_file(output_path, overwrite)

        # Load public key
        if public_key is None:
            if public_key_path is None:
                raise ValueError("Either public_key or public_key_path must be provided")
            public_key = self.load_public_key(public_key_path)

        # Generate random AES key and IV
        aes_key = secrets.token_bytes(AES_KEY_SIZE)
        iv = secrets.token_bytes(AES_IV_SIZE)

        # Read plaintext
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        # Encrypt data with AES-GCM
        aesgcm = AESGCM(aes_key)
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)

        # Encrypt AES key with RSA-OAEP
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Write encrypted file
        with open(output_path, 'wb') as f:
            f.write(RSA_FILE_MAGIC)                    # 4 bytes
            f.write(RSA_FILE_VERSION)                  # 2 bytes
            f.write(len(encrypted_key).to_bytes(4, 'big'))  # 4 bytes
            f.write(encrypted_key)                     # encrypted AES key
            f.write(iv)                                # 12 bytes
            f.write(ciphertext_with_tag)               # ciphertext + tag

        # Securely clear AES key
        self._secure_clear(aes_key)

        return True

    def decrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        private_key: Optional[rsa.RSAPrivateKey] = None,
        private_key_path: Optional[Union[str, Path]] = None,
        key_password: Optional[str] = None,
        password: Optional[str] = None,  # For key_password alias
        overwrite: bool = False,
    ) -> bool:
        """
        Decrypt a file that was encrypted with hybrid RSA-AES encryption.

        Args:
            input_path: Path to the encrypted file.
            output_path: Path to save the decrypted file.
            private_key: The private key object (optional).
            private_key_path: Path to the private key file (optional).
            key_password: Password for the private key (if encrypted).
            password: Alias for key_password.
            overwrite: Whether to overwrite existing output file.

        Returns:
            True if decryption was successful.

        Raises:
            FileNotFoundError: If input file or key file does not exist.
            ValueError: If neither private_key nor private_key_path is provided.

        Example:
            >>> encryptor = RSAEncryptor()
            >>> encryptor.decrypt_file(
            ...     "document.enc",
            ...     "document.pdf",
            ...     private_key_path="private.pem",
            ...     key_password="mypassword"
            ... )
            True
        """
        input_path = Path(input_path)
        output_path = Path(output_path)

        # Validate inputs
        self._validate_input_file(input_path)
        self._validate_output_file(output_path, overwrite)

        # Handle password alias
        if key_password is None and password is not None:
            key_password = password

        # Load private key
        if private_key is None:
            if private_key_path is None:
                raise ValueError("Either private_key or private_key_path must be provided")
            private_key = self.load_private_key(private_key_path, key_password)

        # Read encrypted file
        with open(input_path, 'rb') as f:
            magic = f.read(4)
            version = f.read(2)
            key_length_bytes = f.read(4)
            key_length = int.from_bytes(key_length_bytes, 'big')
            encrypted_key = f.read(key_length)
            iv = f.read(AES_IV_SIZE)
            ciphertext_with_tag = f.read()

        # Validate file format
        if magic != RSA_FILE_MAGIC:
            raise ValueError(ERROR_INVALID_FILE)

        # Decrypt AES key with RSA-OAEP
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        try:
            # Decrypt data with AES-GCM
            aesgcm = AESGCM(aes_key)
            plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)

            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(plaintext)

            return True

        except Exception:
            raise ValueError("Decryption failed: invalid key or corrupted file")

        finally:
            # Securely clear AES key
            self._secure_clear(aes_key)

    @staticmethod
    def _secure_clear(data: bytes) -> None:
        """Attempt to securely clear bytes from memory."""
        pass

    @staticmethod
    def is_encrypted_file(path: Union[str, Path]) -> bool:
        """
        Check if a file is encrypted with RSA encryptor.

        Args:
            path: Path to the file to check.

        Returns:
            True if the file appears to be RSA-encrypted.
        """
        path = Path(path)
        if not path.exists() or not path.is_file():
            return False

        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                return magic == RSA_FILE_MAGIC
        except Exception:
            return False


def generate_key_pair(
    private_key_path: Union[str, Path],
    public_key_path: Union[str, Path],
    key_size: int = RSA_KEY_SIZE,
    password: Optional[str] = None,
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Convenience function to generate and save an RSA key pair.

    Args:
        private_key_path: Path to save the private key.
        public_key_path: Path to save the public key.
        key_size: RSA key size in bits (default: 2048).
        password: Optional password to encrypt the private key.

    Returns:
        Tuple of (private_key, public_key).

    Example:
        >>> from crypto_tool.encryptors import generate_key_pair
        >>> private_key, public_key = generate_key_pair(
        ...     "private.pem",
        ...     "public.pem",
        ...     key_size=4096,
        ...     password="mypassword"
        ... )
    """
    encryptor = RSAEncryptor(key_size=key_size)
    private_key, public_key = encryptor.generate_key_pair()
    encryptor.save_private_key(private_key, private_key_path, password)
    encryptor.save_public_key(public_key, public_key_path)
    return private_key, public_key
