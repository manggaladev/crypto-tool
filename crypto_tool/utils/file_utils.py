"""
File utilities module.

This module provides file and folder handling utilities for the crypto-tool package.
"""

import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Generator, List, Optional, Union


def get_file_size(path: Union[str, Path]) -> int:
    """
    Get the size of a file in bytes.

    Args:
        path: Path to the file.

    Returns:
        File size in bytes.
    """
    path = Path(path)
    return path.stat().st_size


def format_size(size_bytes: int) -> str:
    """
    Format a file size in human-readable format.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Human-readable string (e.g., "1.5 MB").
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def ensure_directory(path: Union[str, Path]) -> Path:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        path: Path to the directory.

    Returns:
        Path object for the directory.
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def list_files(
    directory: Union[str, Path],
    pattern: str = "*",
    recursive: bool = True,
) -> List[Path]:
    """
    List files in a directory.

    Args:
        directory: Path to the directory.
        pattern: Glob pattern to match files.
        recursive: Whether to search recursively.

    Returns:
        List of file paths.
    """
    directory = Path(directory)

    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    if recursive:
        return list(directory.rglob(pattern))
    else:
        return list(directory.glob(pattern))


def create_temp_directory() -> Path:
    """
    Create a temporary directory.

    Returns:
        Path to the temporary directory.
    """
    return Path(tempfile.mkdtemp())


def create_temp_file(suffix: Optional[str] = None) -> Path:
    """
    Create a temporary file.

    Args:
        suffix: Optional file suffix/extension.

    Returns:
        Path to the temporary file.
    """
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return Path(path)


def zip_directory(
    source_dir: Union[str, Path],
    output_path: Union[str, Path],
    compression: int = zipfile.ZIP_DEFLATED,
) -> Path:
    """
    Create a ZIP archive of a directory.

    Args:
        source_dir: Path to the directory to zip.
        output_path: Path for the output ZIP file.
        compression: ZIP compression method.

    Returns:
        Path to the created ZIP file.
    """
    source_dir = Path(source_dir)
    output_path = Path(output_path)

    if not source_dir.exists():
        raise FileNotFoundError(f"Directory not found: {source_dir}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(output_path, 'w', compression) as zf:
        for file_path in source_dir.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(source_dir)
                zf.write(file_path, arcname)

    return output_path


def unzip_archive(
    archive_path: Union[str, Path],
    output_dir: Union[str, Path],
) -> Path:
    """
    Extract a ZIP archive.

    Args:
        archive_path: Path to the ZIP file.
        output_dir: Directory to extract to.

    Returns:
        Path to the extraction directory.
    """
    archive_path = Path(archive_path)
    output_dir = Path(output_dir)

    if not archive_path.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    output_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(archive_path, 'r') as zf:
        zf.extractall(output_dir)

    return output_dir


def secure_delete(path: Union[str, Path], passes: int = 3) -> None:
    """
    Securely delete a file by overwriting it before deletion.

    Args:
        path: Path to the file to delete.
        passes: Number of overwrite passes.

    Note:
        This is a best-effort implementation. For maximum security,
        use specialized tools or libraries.
    """
    path = Path(path)

    if not path.exists():
        return

    if path.is_file():
        # Overwrite with random data
        file_size = path.stat().st_size
        with open(path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())

        # Delete the file
        path.unlink()

    elif path.is_dir():
        shutil.rmtree(path)


def copy_file_metadata(source: Union[str, Path], destination: Union[str, Path]) -> None:
    """
    Copy file metadata (permissions, timestamps) from source to destination.

    Args:
        source: Source file path.
        destination: Destination file path.
    """
    source = Path(source)
    destination = Path(destination)

    # Copy permissions
    shutil.copymode(source, destination)

    # Copy timestamps
    stat = source.stat()
    os.utime(destination, (stat.st_atime, stat.st_mtime))


def get_unique_filename(
    directory: Union[str, Path],
    base_name: str,
    extension: str = "",
) -> Path:
    """
    Generate a unique filename in a directory.

    Args:
        directory: Directory to check.
        base_name: Base name for the file.
        extension: File extension (with or without dot).

    Returns:
        Path to a unique file.
    """
    directory = Path(directory)

    if extension and not extension.startswith('.'):
        extension = f'.{extension}'

    filename = f"{base_name}{extension}"
    filepath = directory / filename
    counter = 1

    while filepath.exists():
        filename = f"{base_name}_{counter}{extension}"
        filepath = directory / filename
        counter += 1

    return filepath


class TempDirectory:
    """Context manager for temporary directories."""

    def __init__(self, cleanup: bool = True):
        """
        Initialize the temporary directory context manager.

        Args:
            cleanup: Whether to delete the directory on exit.
        """
        self.cleanup = cleanup
        self.path: Optional[Path] = None

    def __enter__(self) -> Path:
        """Create and return the temporary directory."""
        self.path = create_temp_directory()
        return self.path

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Clean up the temporary directory."""
        if self.cleanup and self.path and self.path.exists():
            shutil.rmtree(self.path)


class TempFile:
    """Context manager for temporary files."""

    def __init__(self, suffix: Optional[str] = None, cleanup: bool = True):
        """
        Initialize the temporary file context manager.

        Args:
            suffix: Optional file suffix/extension.
            cleanup: Whether to delete the file on exit.
        """
        self.suffix = suffix
        self.cleanup = cleanup
        self.path: Optional[Path] = None

    def __enter__(self) -> Path:
        """Create and return the temporary file path."""
        self.path = create_temp_file(self.suffix)
        return self.path

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Clean up the temporary file."""
        if self.cleanup and self.path and self.path.exists():
            self.path.unlink()
