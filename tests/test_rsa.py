"""
Tests for RSA Encryptor.
"""

import os
import tempfile
from pathlib import Path

import pytest

from crypto_tool.encryptors import RSAEncryptor, generate_key_pair
from crypto_tool.encryptors.rsa_encryptor import RSA_FILE_MAGIC


class TestRSAEncryptor:
    """Test cases for RSAEncryptor."""

    @pytest.fixture
    def encryptor(self):
        """Create an encryptor instance."""
        return RSAEncryptor(key_size=2048)

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def key_pair(self, encryptor, temp_dir):
        """Generate a key pair for testing."""
        private_key, public_key = encryptor.generate_key_pair()

        private_path = temp_dir / "private.pem"
        public_path = temp_dir / "public.pem"

        encryptor.save_private_key(private_key, private_path)
        encryptor.save_public_key(public_key, public_path)

        return private_path, public_path

    def test_generate_key_pair(self, encryptor, temp_dir):
        """Test RSA key pair generation."""
        private_key, public_key = encryptor.generate_key_pair()

        assert private_key is not None
        assert public_key is not None
        assert private_key.key_size == 2048

    def test_save_load_keys(self, encryptor, temp_dir):
        """Test saving and loading keys."""
        private_key, public_key = encryptor.generate_key_pair()

        private_path = temp_dir / "private.pem"
        public_path = temp_dir / "public.pem"

        encryptor.save_private_key(private_key, private_path)
        encryptor.save_public_key(public_key, public_path)

        assert private_path.exists()
        assert public_path.exists()

        # Load keys
        loaded_private = encryptor.load_private_key(private_path)
        loaded_public = encryptor.load_public_key(public_path)

        assert loaded_private.key_size == 2048

    def test_save_load_encrypted_private_key(self, encryptor, temp_dir):
        """Test saving and loading encrypted private key."""
        private_key, public_key = encryptor.generate_key_pair()

        private_path = temp_dir / "private.pem"

        # Save with password
        encryptor.save_private_key(private_key, private_path, password="secret123")

        # Load without password should fail
        with pytest.raises(Exception):
            encryptor.load_private_key(private_path)

        # Load with correct password
        loaded = encryptor.load_private_key(private_path, password="secret123")
        assert loaded is not None

    def test_encrypt_decrypt_file(self, encryptor, temp_dir, key_pair):
        """Test RSA file encryption and decryption."""
        private_path, public_path = key_pair

        # Create test file
        input_file = temp_dir / "test.txt"
        input_file.write_text("Hello, RSA!")

        encrypted_file = temp_dir / "test.enc"
        decrypted_file = temp_dir / "test_decrypted.txt"

        # Encrypt
        encryptor.encrypt_file(
            input_file, encrypted_file,
            public_key_path=public_path
        )

        assert encrypted_file.exists()

        # Verify magic bytes
        with open(encrypted_file, 'rb') as f:
            magic = f.read(4)
        assert magic == RSA_FILE_MAGIC

        # Decrypt
        encryptor.decrypt_file(
            encrypted_file, decrypted_file,
            private_key_path=private_path
        )

        assert decrypted_file.read_text() == "Hello, RSA!"

    def test_encrypt_decrypt_with_key_objects(self, encryptor, temp_dir):
        """Test encryption with key objects instead of paths."""
        private_key, public_key = encryptor.generate_key_pair()

        input_file = temp_dir / "test.txt"
        input_file.write_text("Test with key objects")

        encrypted_file = temp_dir / "test.enc"
        decrypted_file = temp_dir / "test_decrypted.txt"

        # Encrypt with key object
        encryptor.encrypt_file(
            input_file, encrypted_file,
            public_key=public_key
        )

        # Decrypt with key object
        encryptor.decrypt_file(
            encrypted_file, decrypted_file,
            private_key=private_key
        )

        assert decrypted_file.read_text() == "Test with key objects"

    def test_encrypt_large_file(self, encryptor, temp_dir, key_pair):
        """Test encrypting a file larger than RSA can handle directly."""
        private_path, public_path = key_pair

        # Create a file larger than RSA block size
        input_file = temp_dir / "large.bin"
        data = os.urandom(1024 * 100)  # 100KB
        input_file.write_bytes(data)

        encrypted_file = temp_dir / "large.enc"
        decrypted_file = temp_dir / "large_decrypted.bin"

        encryptor.encrypt_file(input_file, encrypted_file, public_key_path=public_path)
        encryptor.decrypt_file(encrypted_file, decrypted_file, private_key_path=private_path)

        assert decrypted_file.read_bytes() == data

    def test_encrypt_missing_public_key(self, encryptor, temp_dir):
        """Test encryption without providing a public key."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Test")
        encrypted_file = temp_dir / "test.enc"

        with pytest.raises(ValueError, match="public_key or public_key_path"):
            encryptor.encrypt_file(input_file, encrypted_file)

    def test_decrypt_missing_private_key(self, encryptor, temp_dir):
        """Test decryption without providing a private key."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Test")
        encrypted_file = temp_dir / "test.enc"
        decrypted_file = temp_dir / "test.txt"

        # First encrypt with a key
        private_key, public_key = encryptor.generate_key_pair()
        encryptor.encrypt_file(input_file, encrypted_file, public_key=public_key)

        # Try to decrypt without key
        with pytest.raises(ValueError, match="private_key or private_key_path"):
            encryptor.decrypt_file(encrypted_file, decrypted_file)

    def test_is_encrypted_file(self, encryptor, temp_dir, key_pair):
        """Test detection of RSA encrypted files."""
        private_path, public_path = key_pair

        input_file = temp_dir / "test.txt"
        input_file.write_text("Test")

        encrypted_file = temp_dir / "test.enc"

        assert not RSAEncryptor.is_encrypted_file(input_file)

        encryptor.encrypt_file(input_file, encrypted_file, public_key_path=public_path)
        assert RSAEncryptor.is_encrypted_file(encrypted_file)

    def test_invalid_key_size(self):
        """Test that invalid key sizes are rejected."""
        with pytest.raises(ValueError):
            RSAEncryptor(key_size=1024)  # Too small

        with pytest.raises(ValueError):
            RSAEncryptor(key_size=8192)  # Too large


class TestGenerateKeyPair:
    """Test the generate_key_pair convenience function."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_generate_key_pair_function(self, temp_dir):
        """Test the generate_key_pair convenience function."""
        private_path = temp_dir / "private.pem"
        public_path = temp_dir / "public.pem"

        private_key, public_key = generate_key_pair(
            private_path, public_path,
            key_size=2048
        )

        assert private_path.exists()
        assert public_path.exists()
        assert private_key is not None
        assert public_key is not None

    def test_generate_key_pair_with_password(self, temp_dir):
        """Test generating password-protected key pair."""
        private_path = temp_dir / "private.pem"
        public_path = temp_dir / "public.pem"

        generate_key_pair(
            private_path, public_path,
            password="secret123"
        )

        # Private key should be encrypted
        encryptor = RSAEncryptor()

        # Load without password should fail
        with pytest.raises(Exception):
            encryptor.load_private_key(private_path)

        # Load with password should succeed
        loaded = encryptor.load_private_key(private_path, password="secret123")
        assert loaded is not None
