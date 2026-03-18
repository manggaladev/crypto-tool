"""
Key utilities module.

This module provides key generation, loading, and management utilities.
"""

import hashlib
import secrets
from pathlib import Path
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from ..constants import (
    AES_KEY_SIZE,
    PBKDF2_SALT_SIZE,
    PBKDF2_ITERATIONS,
    RSA_KEY_SIZE,
    PRIVATE_KEY_EXT,
    PUBLIC_KEY_EXT,
)


def generate_random_key(length: int = AES_KEY_SIZE) -> bytes:
    """
    Generate a cryptographically secure random key.

    Args:
        length: Key length in bytes (default: 32 for AES-256).

    Returns:
        Random bytes of the specified length.

    Example:
        >>> key = generate_random_key(32)
        >>> len(key)
        32
    """
    return secrets.token_bytes(length)


def derive_key_from_password(
    password: str,
    salt: Optional[bytes] = None,
    iterations: int = PBKDF2_ITERATIONS,
    key_length: int = AES_KEY_SIZE,
) -> Tuple[bytes, bytes]:
    """
    Derive a key from a password using PBKDF2.

    Args:
        password: The password to derive from.
        salt: Optional salt (generated if not provided).
        iterations: Number of PBKDF2 iterations.
        key_length: Desired key length in bytes.

    Returns:
        Tuple of (derived_key, salt).

    Example:
        >>> key, salt = derive_key_from_password("mypassword")
        >>> len(key)
        32
    """
    if salt is None:
        salt = secrets.token_bytes(PBKDF2_SALT_SIZE)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    key = kdf.derive(password.encode('utf-8'))
    return key, salt


def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, bytes]:
    """
    Hash a password using SHA-256 with salt.

    Args:
        password: The password to hash.
        salt: Optional salt (generated if not provided).

    Returns:
        Tuple of (hashed_password_hex, salt).

    Example:
        >>> hashed, salt = hash_password("mypassword")
    """
    if salt is None:
        salt = secrets.token_bytes(PBKDF2_SALT_SIZE)

    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )

    return hashed.hex(), salt


def verify_password(password: str, hashed: str, salt: bytes) -> bool:
    """
    Verify a password against a hash.

    Args:
        password: The password to verify.
        hashed: The stored hash (hex string).
        salt: The salt used for hashing.

    Returns:
        True if the password matches.

    Example:
        >>> hashed, salt = hash_password("mypassword")
        >>> verify_password("mypassword", hashed, salt)
        True
        >>> verify_password("wrongpassword", hashed, salt)
        False
    """
    new_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(new_hash, hashed)


def generate_rsa_key_pair(
    key_size: int = RSA_KEY_SIZE,
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate an RSA key pair.

    Args:
        key_size: Key size in bits (default: 2048).

    Returns:
        Tuple of (private_key, public_key).

    Example:
        >>> private_key, public_key = generate_rsa_key_pair()
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(
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
        >>> private_key, public_key = generate_rsa_key_pair()
        >>> save_private_key(private_key, "private.pem", "mypassword")
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


def save_public_key(
    public_key: rsa.RSAPublicKey,
    path: Union[str, Path],
) -> None:
    """
    Save a public key to a PEM file.

    Args:
        public_key: The public key to save.
        path: Path to save the key.

    Example:
        >>> private_key, public_key = generate_rsa_key_pair()
        >>> save_public_key(public_key, "public.pem")
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

    Example:
        >>> private_key = load_private_key("private.pem", "mypassword")
    """
    path = Path(path)

    with open(path, 'rb') as f:
        pem_data = f.read()

    password_bytes = password.encode('utf-8') if password else None
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=password_bytes,
        backend=default_backend()
    )

    return private_key


def load_public_key(
    path: Union[str, Path],
) -> rsa.RSAPublicKey:
    """
    Load a public key from a PEM file.

    Args:
        path: Path to the key file.

    Returns:
        The public key.

    Example:
        >>> public_key = load_public_key("public.pem")
    """
    path = Path(path)

    with open(path, 'rb') as f:
        pem_data = f.read()

    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )

    return public_key


def get_key_fingerprint(key: Union[rsa.RSAPublicKey, rsa.RSAPrivateKey]) -> str:
    """
    Get the SHA-256 fingerprint of an RSA key.

    Args:
        key: The RSA key (public or private).

    Returns:
        Fingerprint as a hex string.

    Example:
        >>> private_key, public_key = generate_rsa_key_pair()
        >>> fingerprint = get_key_fingerprint(public_key)
    """
    if isinstance(key, rsa.RSAPrivateKey):
        key = key.public_key()

    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    fingerprint = hashlib.sha256(pem).hexdigest()
    return ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))


def generate_key_filename(base_name: str = "key") -> Tuple[str, str]:
    """
    Generate standard filenames for a key pair.

    Args:
        base_name: Base name for the keys.

    Returns:
        Tuple of (private_key_filename, public_key_filename).

    Example:
        >>> private, public = generate_key_filename("mykey")
        >>> private
        'mykey.pem'
        >>> public
        'mykey.pub'
    """
    return f"{base_name}{PRIVATE_KEY_EXT}", f"{base_name}{PUBLIC_KEY_EXT}"
