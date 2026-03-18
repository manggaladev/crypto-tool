"""
Utilities module.

This module provides utility functions for the crypto-tool package.
"""

from .file_utils import (
    get_file_size,
    format_size,
    ensure_directory,
    list_files,
    create_temp_directory,
    create_temp_file,
    zip_directory,
    unzip_archive,
    secure_delete,
    copy_file_metadata,
    get_unique_filename,
    TempDirectory,
    TempFile,
)

from .key_utils import (
    generate_random_key,
    derive_key_from_password,
    hash_password,
    verify_password,
    generate_rsa_key_pair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    get_key_fingerprint,
    generate_key_filename,
)

from .crypto_utils import (
    sha256_hash,
    sha512_hash,
    md5_hash,
    compute_hmac,
    verify_hmac,
    base64_encode,
    base64_decode,
    base64url_encode,
    base64url_decode,
    hex_encode,
    hex_decode,
    generate_random_bytes,
    generate_random_hex,
    constant_time_compare,
    xor_bytes,
    int_to_bytes,
    bytes_to_int,
)

__all__ = [
    # File utilities
    'get_file_size',
    'format_size',
    'ensure_directory',
    'list_files',
    'create_temp_directory',
    'create_temp_file',
    'zip_directory',
    'unzip_archive',
    'secure_delete',
    'copy_file_metadata',
    'get_unique_filename',
    'TempDirectory',
    'TempFile',
    # Key utilities
    'generate_random_key',
    'derive_key_from_password',
    'hash_password',
    'verify_password',
    'generate_rsa_key_pair',
    'save_private_key',
    'save_public_key',
    'load_private_key',
    'load_public_key',
    'get_key_fingerprint',
    'generate_key_filename',
    # Crypto utilities
    'sha256_hash',
    'sha512_hash',
    'md5_hash',
    'compute_hmac',
    'verify_hmac',
    'base64_encode',
    'base64_decode',
    'base64url_encode',
    'base64url_decode',
    'hex_encode',
    'hex_decode',
    'generate_random_bytes',
    'generate_random_hex',
    'constant_time_compare',
    'xor_bytes',
    'int_to_bytes',
    'bytes_to_int',
]
