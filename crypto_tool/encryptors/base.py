"""
Base class for encryptors.

This module provides an abstract base class that defines the interface
for all encryptor implementations in the package.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Union


class BaseEncryptor(ABC):
    """
    Abstract base class for file encryptors.

    All encryptor implementations must inherit from this class and
    implement the encrypt_file and decrypt_file methods.
    """

    @abstractmethod
    def encrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        password: Optional[str] = None,
        **kwargs
    ) -> bool:
        """
        Encrypt a file.

        Args:
            input_path: Path to the input file.
            output_path: Path to save the encrypted file.
            password: Password for encryption (if applicable).
            **kwargs: Additional algorithm-specific parameters.

        Returns:
            True if encryption was successful.

        Raises:
            FileNotFoundError: If input file does not exist.
            ValueError: If parameters are invalid.
        """
        pass

    @abstractmethod
    def decrypt_file(
        self,
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        password: Optional[str] = None,
        **kwargs
    ) -> bool:
        """
        Decrypt a file.

        Args:
            input_path: Path to the encrypted file.
            output_path: Path to save the decrypted file.
            password: Password for decryption (if applicable).
            **kwargs: Additional algorithm-specific parameters.

        Returns:
            True if decryption was successful.

        Raises:
            FileNotFoundError: If input file does not exist.
            ValueError: If parameters are invalid.
            InvalidPasswordError: If password is incorrect.
        """
        pass

    @staticmethod
    def _validate_input_file(path: Path) -> None:
        """Validate that the input file exists."""
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not path.is_file():
            raise ValueError(f"Not a file: {path}")

    @staticmethod
    def _validate_output_file(path: Path, overwrite: bool = False) -> None:
        """Validate that the output path is valid."""
        if path.exists() and not overwrite:
            raise FileExistsError(f"File already exists: {path}")
        # Create parent directories if needed
        path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _validate_password(password: str) -> None:
        """Validate that password is not empty."""
        if not password or not password.strip():
            raise ValueError("Password cannot be empty")
