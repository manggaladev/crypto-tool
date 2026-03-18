"""
Command Line Interface for crypto-tool.

This module provides a CLI for file encryption/decryption using
AES-256-GCM and RSA hybrid encryption.

Usage:
    crypto-tool encrypt --input file.txt --output file.enc --password secret
    crypto-tool decrypt --input file.enc --output file.txt --password secret
    crypto-tool generate-key --output ./keys --type rsa --size 2048
    crypto-tool encrypt-folder --input ./folder --output folder.enc --password secret
    crypto-tool decrypt-folder --input folder.enc --output ./folder --password secret
"""

import os
import sys
import getpass
from pathlib import Path
from typing import Optional

import click

from .encryptors import AESEncryptor, RSAEncryptor, generate_key_pair
from .utils import (
    format_size,
    ensure_directory,
    zip_directory,
    unzip_archive,
    TempDirectory,
)
from .constants import (
    SUCCESS_ENCRYPT,
    SUCCESS_DECRYPT,
    SUCCESS_KEY_GENERATED,
    SUCCESS_FOLDER_ENCRYPT,
    SUCCESS_FOLDER_DECRYPT,
    ERROR_PASSWORD_EMPTY,
    ERROR_FILE_NOT_FOUND,
    RSA_KEY_SIZE,
)


# Color output helpers
def print_success(message: str) -> None:
    """Print a success message in green."""
    click.echo(click.style(f"✓ {message}", fg="green", bold=True))


def print_error(message: str) -> None:
    """Print an error message in red."""
    click.echo(click.style(f"✗ {message}", fg="red", bold=True), err=True)


def print_info(message: str) -> None:
    """Print an info message in blue."""
    click.echo(click.style(f"ℹ {message}", fg="blue"))


def print_warning(message: str) -> None:
    """Print a warning message in yellow."""
    click.echo(click.style(f"⚠ {message}", fg="yellow"))


def get_password(prompt: str = "Enter password", confirm: bool = False) -> str:
    """
    Prompt for password with optional confirmation.

    Args:
        prompt: Password prompt message.
        confirm: Whether to ask for confirmation.

    Returns:
        The entered password.
    """
    while True:
        password = getpass.getpass(f"{prompt}: ")
        if not password:
            print_error(ERROR_PASSWORD_EMPTY)
            continue

        if confirm:
            password2 = getpass.getpass("Confirm password: ")
            if password != password2:
                print_error("Passwords do not match")
                continue

        return password


@click.group()
@click.version_option(version="1.0.0", prog_name="crypto-tool")
def main():
    """
    crypto-tool - A file encryptor/decryptor using AES-256-GCM and RSA.

    Secure file encryption with modern cryptographic algorithms.

    \b
    Examples:
        # Encrypt a file with password
        crypto-tool encrypt -i secret.txt -o secret.enc -p mypassword

        # Decrypt a file
        crypto-tool decrypt -i secret.enc -o secret.txt -p mypassword

        # Generate RSA key pair
        crypto-tool generate-key -o ./keys -t rsa -s 2048

        # Encrypt with RSA public key
        crypto-tool encrypt -i secret.txt -o secret.enc -k public.pem
    """
    pass


@main.command()
@click.option(
    "-i", "--input", "input_path",
    required=True,
    type=click.Path(exists=True),
    help="Input file or folder path.",
)
@click.option(
    "-o", "--output", "output_path",
    required=True,
    type=click.Path(),
    help="Output file path.",
)
@click.option(
    "-p", "--password",
    help="Password for encryption (will prompt if not provided).",
)
@click.option(
    "-k", "--public-key", "public_key_path",
    type=click.Path(exists=True),
    help="Public key file for RSA encryption.",
)
@click.option(
    "-a", "--algorithm",
    type=click.Choice(["aes", "rsa"], case_sensitive=False),
    default="aes",
    help="Encryption algorithm (default: aes).",
)
@click.option(
    "-f", "--force",
    is_flag=True,
    help="Overwrite existing output file.",
)
def encrypt(
    input_path: str,
    output_path: str,
    password: Optional[str],
    public_key_path: Optional[str],
    algorithm: str,
    force: bool,
):
    """
    Encrypt a file using AES-256-GCM or RSA.

    AES encryption uses password-based key derivation (PBKDF2).
    RSA encryption uses hybrid encryption (RSA + AES).

    \b
    Examples:
        crypto-tool encrypt -i secret.txt -o secret.enc -p mypassword
        crypto-tool encrypt -i secret.txt -o secret.enc -k public.pem -a rsa
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    # Check if output exists
    if output_path.exists() and not force:
        print_error(f"Output file already exists: {output_path}")
        print_info("Use --force to overwrite")
        sys.exit(1)

    try:
        if algorithm.lower() == "aes":
            # Get password
            if not password:
                password = get_password("Enter encryption password", confirm=True)

            # Encrypt with AES
            encryptor = AESEncryptor()
            encryptor.encrypt_file(input_path, output_path, password, overwrite=True)

            print_success(SUCCESS_ENCRYPT.format(input=input_path, output=output_path))
            print_info(f"Original size: {format_size(input_path.stat().st_size)}")
            print_info(f"Encrypted size: {format_size(output_path.stat().st_size)}")

        elif algorithm.lower() == "rsa":
            if not public_key_path:
                print_error("RSA encryption requires --public-key option")
                sys.exit(1)

            # Encrypt with RSA
            encryptor = RSAEncryptor()
            encryptor.encrypt_file(
                input_path,
                output_path,
                public_key_path=public_key_path,
                overwrite=True
            )

            print_success(SUCCESS_ENCRYPT.format(input=input_path, output=output_path))
            print_info(f"Original size: {format_size(input_path.stat().st_size)}")
            print_info(f"Encrypted size: {format_size(output_path.stat().st_size)}")

    except FileNotFoundError as e:
        print_error(str(e))
        sys.exit(1)
    except ValueError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Encryption failed: {e}")
        sys.exit(1)


@main.command()
@click.option(
    "-i", "--input", "input_path",
    required=True,
    type=click.Path(exists=True),
    help="Input encrypted file path.",
)
@click.option(
    "-o", "--output", "output_path",
    required=True,
    type=click.Path(),
    help="Output decrypted file path.",
)
@click.option(
    "-p", "--password",
    help="Password for decryption (will prompt if not provided).",
)
@click.option(
    "-k", "--private-key", "private_key_path",
    type=click.Path(exists=True),
    help="Private key file for RSA decryption.",
)
@click.option(
    "--key-password", "key_password",
    help="Password for encrypted private key.",
)
@click.option(
    "-f", "--force",
    is_flag=True,
    help="Overwrite existing output file.",
)
def decrypt(
    input_path: str,
    output_path: str,
    password: Optional[str],
    private_key_path: Optional[str],
    key_password: Optional[str],
    force: bool,
):
    """
    Decrypt a file that was encrypted with AES-256-GCM or RSA.

    \b
    Examples:
        crypto-tool decrypt -i secret.enc -o secret.txt -p mypassword
        crypto-tool decrypt -i secret.enc -o secret.txt -k private.pem
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    # Check if output exists
    if output_path.exists() and not force:
        print_error(f"Output file already exists: {output_path}")
        print_info("Use --force to overwrite")
        sys.exit(1)

    try:
        # Detect encryption type from file header
        with open(input_path, 'rb') as f:
            magic = f.read(4)

        if magic == b"CRYP":
            # AES encrypted
            if not password:
                password = get_password("Enter decryption password")

            encryptor = AESEncryptor()
            encryptor.decrypt_file(input_path, output_path, password, overwrite=True)

            print_success(SUCCESS_DECRYPT.format(input=input_path, output=output_path))

        elif magic == b"RRSA":
            # RSA encrypted
            if not private_key_path:
                print_error("RSA encrypted file requires --private-key option")
                sys.exit(1)

            if not key_password:
                key_password = get_password("Enter private key password (leave empty if none)")

            encryptor = RSAEncryptor()
            encryptor.decrypt_file(
                input_path,
                output_path,
                private_key_path=private_key_path,
                key_password=key_password if key_password else None,
                overwrite=True
            )

            print_success(SUCCESS_DECRYPT.format(input=input_path, output=output_path))

        else:
            print_error("Unknown file format. Not an encrypted file.")
            sys.exit(1)

        print_info(f"Decrypted size: {format_size(output_path.stat().st_size)}")

    except ValueError as e:
        if "Invalid password" in str(e):
            print_error("Invalid password or corrupted file")
        else:
            print_error(str(e))
        sys.exit(1)
    except FileNotFoundError as e:
        print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Decryption failed: {e}")
        sys.exit(1)


@main.command("generate-key")
@click.option(
    "-o", "--output", "output_dir",
    required=True,
    type=click.Path(),
    help="Output directory for key files.",
)
@click.option(
    "-t", "--type", "key_type",
    type=click.Choice(["rsa"], case_sensitive=False),
    default="rsa",
    help="Key type (default: rsa).",
)
@click.option(
    "-s", "--size", "key_size",
    type=int,
    default=RSA_KEY_SIZE,
    help=f"Key size in bits (default: {RSA_KEY_SIZE}).",
)
@click.option(
    "-n", "--name", "key_name",
    default="key",
    help="Base name for key files (default: key).",
)
@click.option(
    "-p", "--password",
    help="Password to encrypt the private key.",
)
def generate_key(
    output_dir: str,
    key_type: str,
    key_size: int,
    key_name: str,
    password: Optional[str],
):
    """
    Generate an RSA key pair.

    Creates a private key (.pem) and public key (.pub) file.

    \b
    Examples:
        crypto-tool generate-key -o ./keys -n mykey
        crypto-tool generate-key -o ./keys -s 4096 -p mypassword
    """
    output_dir = Path(output_dir)

    try:
        # Create output directory
        ensure_directory(output_dir)

        # Get password for private key
        if password is None:
            encrypt_key = click.confirm(
                "Encrypt private key with password?",
                default=True
            )
            if encrypt_key:
                password = get_password("Enter private key password", confirm=True)

        # Generate key pair
        private_key, public_key = generate_key_pair(
            private_key_path=output_dir / f"{key_name}.pem",
            public_key_path=output_dir / f"{key_name}.pub",
            key_size=key_size,
            password=password,
        )

        print_success(SUCCESS_KEY_GENERATED.format(
            private=output_dir / f"{key_name}.pem",
            public=output_dir / f"{key_name}.pub"
        ))
        print_info(f"Key size: {key_size} bits")
        if password:
            print_info("Private key is password protected")

    except Exception as e:
        print_error(f"Key generation failed: {e}")
        sys.exit(1)


@main.command("encrypt-folder")
@click.option(
    "-i", "--input", "input_path",
    required=True,
    type=click.Path(exists=True),
    help="Input folder path.",
)
@click.option(
    "-o", "--output", "output_path",
    required=True,
    type=click.Path(),
    help="Output encrypted file path.",
)
@click.option(
    "-p", "--password",
    help="Password for encryption (will prompt if not provided).",
)
@click.option(
    "-f", "--force",
    is_flag=True,
    help="Overwrite existing output file.",
)
def encrypt_folder(
    input_path: str,
    output_path: str,
    password: Optional[str],
    force: bool,
):
    """
    Encrypt an entire folder.

    The folder is first compressed to a ZIP archive, then encrypted.

    \b
    Examples:
        crypto-tool encrypt-folder -i ./documents -o documents.enc
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    # Validate input
    if not input_path.is_dir():
        print_error(f"Not a directory: {input_path}")
        sys.exit(1)

    # Check if output exists
    if output_path.exists() and not force:
        print_error(f"Output file already exists: {output_path}")
        print_info("Use --force to overwrite")
        sys.exit(1)

    try:
        # Get password
        if not password:
            password = get_password("Enter encryption password", confirm=True)

        with TempDirectory() as temp_dir:
            # Create ZIP archive
            print_info("Compressing folder...")
            zip_path = temp_dir / "archive.zip"
            zip_directory(input_path, zip_path)

            # Encrypt the ZIP
            print_info("Encrypting...")
            encryptor = AESEncryptor()
            encryptor.encrypt_file(zip_path, output_path, password, overwrite=True)

        print_success(SUCCESS_FOLDER_ENCRYPT.format(input=input_path, output=output_path))
        print_info(f"Encrypted size: {format_size(output_path.stat().st_size)}")

    except Exception as e:
        print_error(f"Encryption failed: {e}")
        sys.exit(1)


@main.command("decrypt-folder")
@click.option(
    "-i", "--input", "input_path",
    required=True,
    type=click.Path(exists=True),
    help="Input encrypted file path.",
)
@click.option(
    "-o", "--output", "output_path",
    required=True,
    type=click.Path(),
    help="Output folder path.",
)
@click.option(
    "-p", "--password",
    help="Password for decryption (will prompt if not provided).",
)
@click.option(
    "-f", "--force",
    is_flag=True,
    help="Overwrite existing output folder.",
)
def decrypt_folder(
    input_path: str,
    output_path: str,
    password: Optional[str],
    force: bool,
):
    """
    Decrypt a folder that was encrypted with encrypt-folder.

    \b
    Examples:
        crypto-tool decrypt-folder -i documents.enc -o ./documents
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    # Check if output exists
    if output_path.exists() and not force:
        print_error(f"Output folder already exists: {output_path}")
        print_info("Use --force to overwrite")
        sys.exit(1)

    try:
        # Get password
        if not password:
            password = get_password("Enter decryption password")

        with TempDirectory() as temp_dir:
            # Decrypt to temp ZIP
            print_info("Decrypting...")
            zip_path = temp_dir / "archive.zip"
            encryptor = AESEncryptor()
            encryptor.decrypt_file(input_path, zip_path, password, overwrite=True)

            # Extract ZIP
            print_info("Extracting folder...")
            unzip_archive(zip_path, output_path)

        print_success(SUCCESS_FOLDER_DECRYPT.format(input=input_path, output=output_path))

    except ValueError as e:
        if "Invalid password" in str(e):
            print_error("Invalid password or corrupted file")
        else:
            print_error(str(e))
        sys.exit(1)
    except Exception as e:
        print_error(f"Decryption failed: {e}")
        sys.exit(1)


@main.command("sign")
@click.option(
    "-i", "--input", "input_path",
    required=True,
    type=click.Path(exists=True),
    help="File to sign.",
)
@click.option(
    "-k", "--private-key", "private_key_path",
    required=True,
    type=click.Path(exists=True),
    help="Private key file for signing.",
)
@click.option(
    "-o", "--output", "output_path",
    type=click.Path(),
    help="Output signature file (default: input.sig).",
)
@click.option(
    "-p", "--password",
    help="Password for encrypted private key.",
)
def sign(
    input_path: str,
    private_key_path: str,
    output_path: Optional[str],
    password: Optional[str],
):
    """
    Create a digital signature for a file.

    \b
    Examples:
        crypto-tool sign -i document.pdf -k private.pem
    """
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

    input_path = Path(input_path)
    private_key_path = Path(private_key_path)

    if output_path:
        output_path = Path(output_path)
    else:
        output_path = input_path.with_suffix(input_path.suffix + ".sig")

    try:
        # Load private key
        if not password:
            password = get_password("Enter private key password (leave empty if none)")

        encryptor = RSAEncryptor()
        private_key = encryptor.load_private_key(
            private_key_path,
            password if password else None
        )

        # Read file
        with open(input_path, 'rb') as f:
            data = f.read()

        # Sign
        signature = private_key.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Save signature
        with open(output_path, 'wb') as f:
            f.write(signature)

        print_success(f"File signed: {input_path}")
        print_info(f"Signature saved to: {output_path}")

    except Exception as e:
        print_error(f"Signing failed: {e}")
        sys.exit(1)


@main.command("verify")
@click.option(
    "-i", "--input", "input_path",
    required=True,
    type=click.Path(exists=True),
    help="File to verify.",
)
@click.option(
    "-s", "--signature", "signature_path",
    required=True,
    type=click.Path(exists=True),
    help="Signature file.",
)
@click.option(
    "-k", "--public-key", "public_key_path",
    required=True,
    type=click.Path(exists=True),
    help="Public key file for verification.",
)
def verify(
    input_path: str,
    signature_path: str,
    public_key_path: str,
):
    """
    Verify a digital signature.

    \b
    Examples:
        crypto-tool verify -i document.pdf -s document.pdf.sig -k public.pem
    """
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.exceptions import InvalidSignature

    input_path = Path(input_path)
    signature_path = Path(signature_path)
    public_key_path = Path(public_key_path)

    try:
        # Load public key
        encryptor = RSAEncryptor()
        public_key = encryptor.load_public_key(public_key_path)

        # Read file
        with open(input_path, 'rb') as f:
            data = f.read()

        # Read signature
        with open(signature_path, 'rb') as f:
            signature = f.read()

        # Verify
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print_success("Signature verification successful")
        print_info(f"File: {input_path}")
        print_info(f"Signature: {signature_path}")

    except InvalidSignature:
        print_error("Signature verification failed: Invalid signature")
        sys.exit(1)
    except Exception as e:
        print_error(f"Verification failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
