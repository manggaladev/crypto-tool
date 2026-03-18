"""
Tests for AES Encryptor.
"""

import os
import tempfile
from pathlib import Path

import pytest

from crypto_tool import AESEncryptor
from crypto_tool.constants import FILE_MAGIC


class TestAESEncryptor:
    """Test cases for AESEncryptor."""

    @pytest.fixture
    def encryptor(self):
        """Create an encryptor instance."""
        return AESEncryptor()

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_encrypt_decrypt_small_file(self, encryptor, temp_dir):
        """Test encrypting and decrypting a small file."""
        # Create test file
        input_file = temp_dir / "test.txt"
        input_file.write_text("Hello, World!")

        encrypted_file = temp_dir / "test.enc"
        decrypted_file = temp_dir / "test_decrypted.txt"

        # Encrypt
        result = encryptor.encrypt_file(input_file, encrypted_file, "password123")
        assert result is True
        assert encrypted_file.exists()
        assert encrypted_file.stat().st_size > input_file.stat().st_size

        # Verify magic bytes
        with open(encrypted_file, 'rb') as f:
            magic = f.read(4)
        assert magic == FILE_MAGIC

        # Decrypt
        result = encryptor.decrypt_file(encrypted_file, decrypted_file, "password123")
        assert result is True
        assert decrypted_file.exists()
        assert decrypted_file.read_text() == "Hello, World!"

    def test_encrypt_decrypt_empty_file(self, encryptor, temp_dir):
        """Test encrypting and decrypting an empty file."""
        input_file = temp_dir / "empty.txt"
        input_file.write_text("")

        encrypted_file = temp_dir / "empty.enc"
        decrypted_file = temp_dir / "empty_decrypted.txt"

        encryptor.encrypt_file(input_file, encrypted_file, "password")
        encryptor.decrypt_file(encrypted_file, decrypted_file, "password")

        assert decrypted_file.read_text() == ""

    def test_encrypt_decrypt_large_file(self, encryptor, temp_dir):
        """Test encrypting and decrypting a larger file."""
        input_file = temp_dir / "large.bin"
        # Create 1MB file
        data = os.urandom(1024 * 1024)
        input_file.write_bytes(data)

        encrypted_file = temp_dir / "large.enc"
        decrypted_file = temp_dir / "large_decrypted.bin"

        encryptor.encrypt_file(input_file, encrypted_file, "password")
        encryptor.decrypt_file(encrypted_file, decrypted_file, "password")

        assert decrypted_file.read_bytes() == data

    def test_decrypt_wrong_password(self, encryptor, temp_dir):
        """Test decrypting with wrong password."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Secret message")

        encrypted_file = temp_dir / "test.enc"
        decrypted_file = temp_dir / "test_decrypted.txt"

        encryptor.encrypt_file(input_file, encrypted_file, "correct_password")

        with pytest.raises(ValueError, match="Invalid password"):
            encryptor.decrypt_file(encrypted_file, decrypted_file, "wrong_password")

    def test_encrypt_empty_password(self, encryptor, temp_dir):
        """Test encrypting with empty password."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Test")
        encrypted_file = temp_dir / "test.enc"

        with pytest.raises(ValueError, match="Password cannot be empty"):
            encryptor.encrypt_file(input_file, encrypted_file, "")

    def test_encrypt_nonexistent_file(self, encryptor, temp_dir):
        """Test encrypting a non-existent file."""
        with pytest.raises(FileNotFoundError):
            encryptor.encrypt_file(
                temp_dir / "nonexistent.txt",
                temp_dir / "output.enc",
                "password"
            )

    def test_encrypt_overwrite_protection(self, encryptor, temp_dir):
        """Test that existing files are not overwritten by default."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Test")

        encrypted_file = temp_dir / "test.enc"
        encrypted_file.write_text("Existing content")

        with pytest.raises(FileExistsError):
            encryptor.encrypt_file(input_file, encrypted_file, "password", overwrite=False)

    def test_encrypt_overwrite_enabled(self, encryptor, temp_dir):
        """Test that files can be overwritten when enabled."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Test")

        encrypted_file = temp_dir / "test.enc"
        encrypted_file.write_text("Existing content")

        encryptor.encrypt_file(input_file, encrypted_file, "password", overwrite=True)

        # Verify it was overwritten
        with open(encrypted_file, 'rb') as f:
            magic = f.read(4)
        assert magic == FILE_MAGIC

    def test_is_encrypted_file(self, encryptor, temp_dir):
        """Test detection of encrypted files."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Test")

        encrypted_file = temp_dir / "test.enc"

        assert not AESEncryptor.is_encrypted_file(input_file)

        encryptor.encrypt_file(input_file, encrypted_file, "password")
        assert AESEncryptor.is_encrypted_file(encrypted_file)

    def test_encrypt_decrypt_data(self, encryptor):
        """Test encrypting and decrypting data in memory."""
        data = b"Hello, World!"

        encrypted = encryptor.encrypt_data(data, "password")
        assert encrypted != data
        assert encrypted.startswith(FILE_MAGIC)

        decrypted = encryptor.decrypt_data(encrypted, "password")
        assert decrypted == data


class TestAESEncryptorKeyDerivation:
    """Test key derivation functionality."""

    @pytest.fixture
    def encryptor(self):
        return AESEncryptor(iterations=10000)  # Lower iterations for faster tests

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_different_salts_different_ciphertext(self, encryptor, temp_dir):
        """Test that encrypting the same file twice produces different ciphertext."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Same content")

        encrypted1 = temp_dir / "enc1.enc"
        encrypted2 = temp_dir / "enc2.enc"

        encryptor.encrypt_file(input_file, encrypted1, "password")
        encryptor.encrypt_file(input_file, encrypted2, "password")

        # Files should be different due to random salt/IV
        assert encrypted1.read_bytes() != encrypted2.read_bytes()

        # But both should decrypt to the same content
        decrypted1 = temp_dir / "dec1.txt"
        decrypted2 = temp_dir / "dec2.txt"

        encryptor.decrypt_file(encrypted1, decrypted1, "password")
        encryptor.decrypt_file(encrypted2, decrypted2, "password")

        assert decrypted1.read_text() == decrypted2.read_text() == "Same content"
