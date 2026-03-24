"""
Tests for CLI.
"""

import os
import tempfile
from pathlib import Path
from click.testing import CliRunner

import pytest

from crypto_tool.cli import main


class TestCLI:
    """Test cases for CLI commands."""

    @pytest.fixture
    def runner(self):
        """Create a CLI runner."""
        return CliRunner()

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_version(self, runner):
        """Test --version option."""
        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        assert 'crypto-tool' in result.output

    def test_help(self, runner):
        """Test --help option."""
        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'encrypt' in result.output
        assert 'decrypt' in result.output
        assert 'generate-key' in result.output

    def test_encrypt_decrypt_file(self, runner, temp_dir):
        """Test encrypt and decrypt commands."""
        # Create test file
        input_file = temp_dir / "test.txt"
        input_file.write_text("Hello, CLI!")

        encrypted_file = temp_dir / "test.enc"
        decrypted_file = temp_dir / "test_decrypted.txt"

        # Encrypt
        result = runner.invoke(main, [
            'encrypt',
            '-i', str(input_file),
            '-o', str(encrypted_file),
            '-p', 'testpassword'
        ])

        assert result.exit_code == 0
        assert encrypted_file.exists()
        assert 'Successfully encrypted' in result.output

        # Decrypt
        result = runner.invoke(main, [
            'decrypt',
            '-i', str(encrypted_file),
            '-o', str(decrypted_file),
            '-p', 'testpassword'
        ])

        assert result.exit_code == 0
        assert decrypted_file.exists()
        assert decrypted_file.read_text() == "Hello, CLI!"

    def test_encrypt_missing_input(self, runner, temp_dir):
        """Test encrypt with missing input file."""
        result = runner.invoke(main, [
            'encrypt',
            '-i', str(temp_dir / "nonexistent.txt"),
            '-o', str(temp_dir / "output.enc"),
            '-p', 'password'
        ])

        assert result.exit_code != 0

    def test_encrypt_missing_password(self, runner, temp_dir):
        """Test encrypt without password."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Test")

        result = runner.invoke(main, [
            'encrypt',
            '-i', str(input_file),
            '-o', str(temp_dir / "output.enc")
        ])

        # Should fail or prompt (in non-interactive mode, fails)
        assert result.exit_code != 0 or 'Password cannot be empty' in result.output

    def test_decrypt_wrong_password(self, runner, temp_dir):
        """Test decrypt with wrong password."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Secret")

        encrypted_file = temp_dir / "test.enc"
        decrypted_file = temp_dir / "test_decrypted.txt"

        # Encrypt with correct password
        runner.invoke(main, [
            'encrypt',
            '-i', str(input_file),
            '-o', str(encrypted_file),
            '-p', 'correct_password'
        ])

        # Try to decrypt with wrong password
        result = runner.invoke(main, [
            'decrypt',
            '-i', str(encrypted_file),
            '-o', str(decrypted_file),
            '-p', 'wrong_password'
        ])

        assert result.exit_code != 0
        assert 'Invalid password' in result.output or 'error' in result.output.lower()

    def test_generate_key(self, runner, temp_dir):
        """Test generate-key command."""
        key_dir = temp_dir / "keys"

        result = runner.invoke(main, [
            'generate-key',
            '-o', str(key_dir),
            '-t', 'rsa',
            '-s', '2048',
            '-n', 'mykey',
            '-p', ''  # Empty password for non-interactive mode
        ])

        assert result.exit_code == 0
        assert (key_dir / "mykey.pem").exists()
        assert (key_dir / "mykey.pub").exists()
        assert 'Successfully generated' in result.output

    def test_encrypt_decrypt_folder(self, runner, temp_dir):
        """Test encrypt-folder and decrypt-folder commands."""
        # Create test folder with files
        folder = temp_dir / "test_folder"
        folder.mkdir()
        (folder / "file1.txt").write_text("Content 1")
        (folder / "file2.txt").write_text("Content 2")

        encrypted_file = temp_dir / "folder.enc"
        decrypted_folder = temp_dir / "decrypted_folder"

        # Encrypt folder
        result = runner.invoke(main, [
            'encrypt-folder',
            '-i', str(folder),
            '-o', str(encrypted_file),
            '-p', 'folderpassword'
        ])

        assert result.exit_code == 0
        assert encrypted_file.exists()

        # Decrypt folder
        result = runner.invoke(main, [
            'decrypt-folder',
            '-i', str(encrypted_file),
            '-o', str(decrypted_folder),
            '-p', 'folderpassword'
        ])

        assert result.exit_code == 0
        assert (decrypted_folder / "file1.txt").exists()
        assert (decrypted_folder / "file2.txt").exists()
        assert (decrypted_folder / "file1.txt").read_text() == "Content 1"
        assert (decrypted_folder / "file2.txt").read_text() == "Content 2"

    def test_force_overwrite(self, runner, temp_dir):
        """Test --force option for overwriting files."""
        input_file = temp_dir / "test.txt"
        input_file.write_text("Test")

        output_file = temp_dir / "test.enc"
        output_file.write_text("Existing content")

        # Should fail without --force
        result = runner.invoke(main, [
            'encrypt',
            '-i', str(input_file),
            '-o', str(output_file),
            '-p', 'password'
        ])

        assert result.exit_code != 0
        assert 'already exists' in result.output

        # Should succeed with --force
        result = runner.invoke(main, [
            'encrypt',
            '-i', str(input_file),
            '-o', str(output_file),
            '-p', 'password',
            '-f'
        ])

        assert result.exit_code == 0

    def test_rsa_encrypt_decrypt(self, runner, temp_dir):
        """Test RSA encryption via CLI."""
        # Generate keys with empty password
        key_dir = temp_dir / "keys"
        gen_result = runner.invoke(main, [
            'generate-key',
            '-o', str(key_dir),
            '-n', 'testkey',
            '-p', ''  # Empty password for non-interactive mode
        ])
        assert gen_result.exit_code == 0, f"Key generation failed: {gen_result.output}"

        # Create test file
        input_file = temp_dir / "test.txt"
        input_file.write_text("RSA Test")

        encrypted_file = temp_dir / "test.enc"
        decrypted_file = temp_dir / "test_decrypted.txt"

        # Encrypt with RSA
        result = runner.invoke(main, [
            'encrypt',
            '-i', str(input_file),
            '-o', str(encrypted_file),
            '-k', str(key_dir / "testkey.pub"),
            '-a', 'rsa'
        ])

        assert result.exit_code == 0, f"Encryption failed: {result.output}"

        # Decrypt with RSA
        result = runner.invoke(main, [
            'decrypt',
            '-i', str(encrypted_file),
            '-o', str(decrypted_file),
            '-k', str(key_dir / "testkey.pem"),
            '--key-password', ''
        ])

        assert result.exit_code == 0, f"Decryption failed: {result.output}"
        assert decrypted_file.read_text() == "RSA Test"
