"""
Crypto utilities module.

This module provides helper functions for cryptographic operations.
"""

import base64
import hashlib
import secrets
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend


def sha256_hash(data: Union[str, bytes]) -> str:
    """
    Calculate SHA-256 hash of data.

    Args:
        data: Data to hash (string or bytes).

    Returns:
        Hex-encoded hash string.

    Example:
        >>> sha256_hash("hello world")
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def sha512_hash(data: Union[str, bytes]) -> str:
    """
    Calculate SHA-512 hash of data.

    Args:
        data: Data to hash (string or bytes).

    Returns:
        Hex-encoded hash string.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha512(data).hexdigest()


def md5_hash(data: Union[str, bytes]) -> str:
    """
    Calculate MD5 hash of data.

    Warning:
        MD5 is not recommended for cryptographic purposes.
        Use SHA-256 or SHA-512 instead.

    Args:
        data: Data to hash (string or bytes).

    Returns:
        Hex-encoded hash string.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()


def compute_hmac(
    key: bytes,
    data: Union[str, bytes],
    algorithm: str = "sha256",
) -> bytes:
    """
    Compute HMAC for data.

    Args:
        key: HMAC key.
        data: Data to authenticate.
        algorithm: Hash algorithm ('sha256', 'sha512').

    Returns:
        HMAC bytes.

    Example:
        >>> key = b'secret_key'
        >>> h = compute_hmac(key, 'message')
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    if algorithm == "sha256":
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    elif algorithm == "sha512":
        h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    h.update(data)
    return h.finalize()


def verify_hmac(
    key: bytes,
    data: Union[str, bytes],
    expected_hmac: bytes,
    algorithm: str = "sha256",
) -> bool:
    """
    Verify HMAC for data.

    Args:
        key: HMAC key.
        data: Data to verify.
        expected_hmac: Expected HMAC value.
        algorithm: Hash algorithm ('sha256', 'sha512').

    Returns:
        True if HMAC is valid.

    Example:
        >>> key = b'secret_key'
        >>> h = compute_hmac(key, 'message')
        >>> verify_hmac(key, 'message', h)
        True
    """
    computed_hmac = compute_hmac(key, data, algorithm)
    return secrets.compare_digest(computed_hmac, expected_hmac)


def base64_encode(data: Union[str, bytes]) -> str:
    """
    Encode data as Base64.

    Args:
        data: Data to encode.

    Returns:
        Base64-encoded string.

    Example:
        >>> base64_encode(b'hello')
        'aGVsbG8='
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('ascii')


def base64_decode(data: str) -> bytes:
    """
    Decode Base64 data.

    Args:
        data: Base64-encoded string.

    Returns:
        Decoded bytes.

    Example:
        >>> base64_decode('aGVsbG8=')
        b'hello'
    """
    return base64.b64decode(data)


def base64url_encode(data: Union[str, bytes]) -> str:
    """
    Encode data as URL-safe Base64.

    Args:
        data: Data to encode.

    Returns:
        URL-safe Base64-encoded string.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def base64url_decode(data: str) -> bytes:
    """
    Decode URL-safe Base64 data.

    Args:
        data: URL-safe Base64-encoded string.

    Returns:
        Decoded bytes.
    """
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def hex_encode(data: bytes) -> str:
    """
    Encode bytes as hexadecimal string.

    Args:
        data: Bytes to encode.

    Returns:
        Hex-encoded string.
    """
    return data.hex()


def hex_decode(data: str) -> bytes:
    """
    Decode hexadecimal string to bytes.

    Args:
        data: Hex-encoded string.

    Returns:
        Decoded bytes.
    """
    return bytes.fromhex(data)


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        length: Number of bytes to generate.

    Returns:
        Random bytes.

    Example:
        >>> random_bytes = generate_random_bytes(16)
        >>> len(random_bytes)
        16
    """
    return secrets.token_bytes(length)


def generate_random_hex(length: int) -> str:
    """
    Generate random hexadecimal string.

    Args:
        length: Length of hex string (will generate length/2 bytes).

    Returns:
        Hex-encoded random string.

    Example:
        >>> random_hex = generate_random_hex(32)
        >>> len(random_hex)
        32
    """
    return secrets.token_hex(length // 2)


def constant_time_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """
    Compare two values in constant time to prevent timing attacks.

    Args:
        a: First value.
        b: Second value.

    Returns:
        True if values are equal.

    Example:
        >>> constant_time_compare('secret', 'secret')
        True
        >>> constant_time_compare('secret', 'wrong')
        False
    """
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    return secrets.compare_digest(a, b)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        XOR result.

    Raises:
        ValueError: If strings have different lengths.
    """
    if len(a) != len(b):
        raise ValueError("Byte strings must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def int_to_bytes(n: int, length: Optional[int] = None) -> bytes:
    """
    Convert integer to bytes.

    Args:
        n: Integer to convert.
        length: Optional length (will pad or raise error).

    Returns:
        Bytes representation.
    """
    if n == 0:
        return b'\x00' if length is None else b'\x00' * length

    byte_length = (n.bit_length() + 7) // 8
    result = n.to_bytes(byte_length, 'big')

    if length is not None:
        if len(result) > length:
            raise ValueError(f"Integer too large for {length} bytes")
        result = b'\x00' * (length - len(result)) + result

    return result


def bytes_to_int(b: bytes) -> int:
    """
    Convert bytes to integer.

    Args:
        b: Bytes to convert.

    Returns:
        Integer value.
    """
    return int.from_bytes(b, 'big')
