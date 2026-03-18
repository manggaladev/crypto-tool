"""
Constants for the crypto-tool package.

This module defines all the constants used throughout the package,
including key sizes, iteration counts, and file format specifications.
"""

# AES Constants
AES_KEY_SIZE = 32  # 256 bits = 32 bytes
AES_IV_SIZE = 12   # 96 bits = 12 bytes (recommended for GCM)
AES_TAG_SIZE = 16  # 128 bits = 16 bytes (authentication tag)

# PBKDF2 Constants
PBKDF2_SALT_SIZE = 16  # 128 bits = 16 bytes
PBKDF2_ITERATIONS = 100000  # Minimum recommended iterations
PBKDF2_ALGORITHM = "SHA256"

# RSA Constants
RSA_KEY_SIZE = 2048  # Default RSA key size
RSA_MIN_KEY_SIZE = 2048
RSA_MAX_KEY_SIZE = 4096

# File Format Constants
# Encrypted file header format:
# [MAGIC (4 bytes)] [VERSION (2 bytes)] [SALT (16 bytes)] [IV (12 bytes)] [TAG (16 bytes)] [CIPHERTEXT]
FILE_MAGIC = b"CRYP"  # Magic bytes to identify encrypted files
FILE_VERSION = b"\x01\x00"  # Version 1.0
HEADER_SIZE = 4 + 2 + PBKDF2_SALT_SIZE + AES_IV_SIZE + AES_TAG_SIZE  # Total header size

# RSA Key File Extensions
PRIVATE_KEY_EXT = ".pem"
PUBLIC_KEY_EXT = ".pub"

# Encrypted File Extension
ENCRYPTED_EXT = ".enc"

# Signature Extension
SIGNATURE_EXT = ".sig"

# Error Messages
ERROR_PASSWORD_EMPTY = "Password cannot be empty"
ERROR_FILE_NOT_FOUND = "File not found: {path}"
ERROR_FILE_EXISTS = "File already exists: {path}"
ERROR_INVALID_PASSWORD = "Invalid password or corrupted file"
ERROR_INVALID_FILE = "Invalid encrypted file format"
ERROR_FOLDER_NOT_FOUND = "Folder not found: {path}"
ERROR_KEY_GENERATION = "Failed to generate key pair: {error}"
ERROR_INVALID_KEY = "Invalid key file: {path}"

# Success Messages
SUCCESS_ENCRYPT = "Successfully encrypted: {input} -> {output}"
SUCCESS_DECRYPT = "Successfully decrypted: {input} -> {output}"
SUCCESS_KEY_GENERATED = "Successfully generated key pair: {private}, {public}"
SUCCESS_SIGN = "Successfully signed: {file}"
SUCCESS_VERIFY = "Signature verification successful"
SUCCESS_FOLDER_ENCRYPT = "Successfully encrypted folder: {input} -> {output}"
SUCCESS_FOLDER_DECRYPT = "Successfully decrypted folder: {input} -> {output}"
