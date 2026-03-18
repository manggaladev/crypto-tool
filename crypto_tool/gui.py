"""
Graphical User Interface for crypto-tool.

This module provides a GUI for file encryption/decryption using tkinter.

Usage:
    python -m crypto_tool.gui
    # or
    crypto-tool-gui
"""

import os
import sys
import threading
from pathlib import Path
from typing import Optional, Callable

# Try to import tkinter
try:
    import tkinter as tk
    from tkinter import (
        ttk,
        filedialog,
        messagebox,
        scrolledtext,
    )
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

from .encryptors import AESEncryptor, RSAEncryptor
from .utils import format_size, ensure_directory
from .constants import RSA_KEY_SIZE


class CryptoToolGUI:
    """
    Main GUI class for crypto-tool.

    Provides a graphical interface for:
    - File encryption/decryption (AES)
    - RSA key generation
    - Folder encryption/decryption
    """

    def __init__(self, root: Optional[tk.Tk] = None):
        """
        Initialize the GUI.

        Args:
            root: Optional existing Tk root window.
        """
        if not TKINTER_AVAILABLE:
            raise RuntimeError("tkinter is not available. Please install Python with tkinter support.")

        if root is None:
            self.root = tk.Tk()
        else:
            self.root = root

        self.root.title("crypto-tool - File Encryptor")
        self.root.geometry("700x600")
        self.root.minsize(600, 500)

        # Variables
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.algorithm = tk.StringVar(value="aes")
        self.public_key_path = tk.StringVar()
        self.private_key_path = tk.StringVar()

        # Build UI
        self._create_widgets()

    def _create_widgets(self) -> None:
        """Create all GUI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Input file section
        input_frame = ttk.LabelFrame(main_frame, text="Input", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="File/Folder:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(input_frame, textvariable=self.input_path, width=50).grid(
            row=0, column=1, padx=5, sticky=tk.EW
        )
        ttk.Button(input_frame, text="Browse...", command=self._browse_input).grid(
            row=0, column=2, padx=5
        )

        input_frame.columnconfigure(1, weight=1)

        # Output file section
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="10")
        output_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(output_frame, text="Output File:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(output_frame, textvariable=self.output_path, width=50).grid(
            row=0, column=1, padx=5, sticky=tk.EW
        )
        ttk.Button(output_frame, text="Browse...", command=self._browse_output).grid(
            row=0, column=2, padx=5
        )

        output_frame.columnconfigure(1, weight=1)

        # Algorithm selection
        algo_frame = ttk.LabelFrame(main_frame, text="Algorithm", padding="10")
        algo_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Radiobutton(
            algo_frame, text="AES-256-GCM (Password)", variable=self.algorithm, value="aes"
        ).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(
            algo_frame, text="RSA (Key Pair)", variable=self.algorithm, value="rsa"
        ).pack(side=tk.LEFT, padx=10)

        # Password section (for AES)
        password_frame = ttk.LabelFrame(main_frame, text="Password (AES)", padding="10")
        password_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(password_frame, text="Password:").grid(row=0, column=0, sticky=tk.W)
        password_entry = ttk.Entry(
            password_frame, textvariable=self.password, width=50, show="*"
        )
        password_entry.grid(row=0, column=1, padx=5, sticky=tk.EW)

        show_btn = ttk.Checkbutton(
            password_frame, text="Show", variable=self.show_password,
            command=lambda: password_entry.configure(show="" if self.show_password.get() else "*")
        )
        show_btn.grid(row=0, column=2, padx=5)

        password_frame.columnconfigure(1, weight=1)

        # Key section (for RSA)
        key_frame = ttk.LabelFrame(main_frame, text="Keys (RSA)", padding="10")
        key_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(key_frame, text="Public Key:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(key_frame, textvariable=self.public_key_path, width=40).grid(
            row=0, column=1, padx=5, sticky=tk.EW
        )
        ttk.Button(key_frame, text="Browse...", command=self._browse_public_key).grid(
            row=0, column=2, padx=5
        )

        ttk.Label(key_frame, text="Private Key:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(key_frame, textvariable=self.private_key_path, width=40).grid(
            row=1, column=1, padx=5, sticky=tk.EW
        )
        ttk.Button(key_frame, text="Browse...", command=self._browse_private_key).grid(
            row=1, column=2, padx=5
        )

        ttk.Button(key_frame, text="Generate Key Pair", command=self._generate_keys).grid(
            row=2, column=0, columnspan=3, pady=10
        )

        key_frame.columnconfigure(1, weight=1)

        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(
            action_frame, text="🔒 Encrypt", command=self._encrypt, width=15
        ).pack(side=tk.LEFT, padx=5, expand=True)
        ttk.Button(
            action_frame, text="🔓 Decrypt", command=self._decrypt, width=15
        ).pack(side=tk.LEFT, padx=5, expand=True)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(0, 10))

        # Log area
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _browse_input(self) -> None:
        """Browse for input file or folder."""
        # Ask for file
        file_path = filedialog.askopenfilename(title="Select File")
        if file_path:
            self.input_path.set(file_path)
            # Auto-set output path
            path = Path(file_path)
            if path.suffix == ".enc":
                # Decrypting
                self.output_path.set(str(path.with_suffix("")))
            else:
                # Encrypting
                self.output_path.set(str(path) + ".enc")
            return

        # Ask for folder
        folder_path = filedialog.askdirectory(title="Select Folder")
        if folder_path:
            self.input_path.set(folder_path)
            self.output_path.set(folder_path + ".enc")

    def _browse_output(self) -> None:
        """Browse for output file."""
        file_path = filedialog.asksaveasfilename(
            title="Save As",
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if file_path:
            self.output_path.set(file_path)

    def _browse_public_key(self) -> None:
        """Browse for public key file."""
        file_path = filedialog.askopenfilename(
            title="Select Public Key",
            filetypes=[("PEM files", "*.pem *.pub"), ("All files", "*.*")]
        )
        if file_path:
            self.public_key_path.set(file_path)

    def _browse_private_key(self) -> None:
        """Browse for private key file."""
        file_path = filedialog.askopenfilename(
            title="Select Private Key",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if file_path:
            self.private_key_path.set(file_path)

    def _generate_keys(self) -> None:
        """Generate RSA key pair."""
        # Ask for output directory
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if not output_dir:
            return

        output_dir = Path(output_dir)

        try:
            self._log("Generating RSA key pair...")
            self.progress.start()

            def generate():
                try:
                    private_path = output_dir / "private.pem"
                    public_path = output_dir / "public.pub"

                    private_key, public_key = RSAEncryptor().generate_key_pair()
                    RSAEncryptor().save_private_key(private_key, private_path)
                    RSAEncryptor().save_public_key(public_key, public_path)

                    self.root.after(0, lambda: self._log(f"✓ Private key: {private_path}"))
                    self.root.after(0, lambda: self._log(f"✓ Public key: {public_path}"))
                    self.root.after(0, lambda: self._log("Key pair generated successfully!"))

                    self.private_key_path.set(str(private_path))
                    self.public_key_path.set(str(public_path))

                except Exception as e:
                    self.root.after(0, lambda: self._log(f"✗ Error: {e}"))
                finally:
                    self.root.after(0, self.progress.stop)

            threading.Thread(target=generate, daemon=True).start()

        except Exception as e:
            self.progress.stop()
            self._log(f"✗ Error: {e}")
            messagebox.showerror("Error", str(e))

    def _encrypt(self) -> None:
        """Encrypt the selected file."""
        input_p = self.input_path.get()
        output_p = self.output_path.get()

        if not input_p or not output_p:
            messagebox.showwarning("Warning", "Please select input and output files")
            return

        input_path = Path(input_p)
        output_path = Path(output_p)

        algo = self.algorithm.get()

        if algo == "aes":
            password = self.password.get()
            if not password:
                messagebox.showwarning("Warning", "Please enter a password")
                return
        else:
            if not self.public_key_path.get():
                messagebox.showwarning("Warning", "Please select a public key")
                return

        try:
            self._log(f"Encrypting: {input_path}")
            self.progress.start()

            def encrypt():
                try:
                    if algo == "aes":
                        encryptor = AESEncryptor()
                        encryptor.encrypt_file(
                            input_path, output_path, self.password.get(), overwrite=True
                        )
                    else:
                        encryptor = RSAEncryptor()
                        encryptor.encrypt_file(
                            input_path, output_path,
                            public_key_path=self.public_key_path.get(),
                            overwrite=True
                        )

                    size = format_size(output_path.stat().st_size)
                    self.root.after(0, lambda: self._log(f"✓ Encrypted: {output_path}"))
                    self.root.after(0, lambda: self._log(f"✓ Size: {size}"))
                    self.root.after(0, lambda: messagebox.showinfo("Success", "File encrypted successfully!"))

                except Exception as e:
                    self.root.after(0, lambda: self._log(f"✗ Error: {e}"))
                    self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                finally:
                    self.root.after(0, self.progress.stop)

            threading.Thread(target=encrypt, daemon=True).start()

        except Exception as e:
            self.progress.stop()
            self._log(f"✗ Error: {e}")
            messagebox.showerror("Error", str(e))

    def _decrypt(self) -> None:
        """Decrypt the selected file."""
        input_p = self.input_path.get()
        output_p = self.output_path.get()

        if not input_p or not output_p:
            messagebox.showwarning("Warning", "Please select input and output files")
            return

        input_path = Path(input_p)
        output_path = Path(output_p)

        try:
            self._log(f"Decrypting: {input_path}")
            self.progress.start()

            def decrypt():
                try:
                    # Detect encryption type
                    with open(input_path, 'rb') as f:
                        magic = f.read(4)

                    if magic == b"CRYP":
                        password = self.password.get()
                        if not password:
                            self.root.after(0, lambda: messagebox.showwarning("Warning", "Please enter a password"))
                            return

                        encryptor = AESEncryptor()
                        encryptor.decrypt_file(input_path, output_path, password, overwrite=True)

                    elif magic == b"RRSA":
                        private_key = self.private_key_path.get()
                        if not private_key:
                            self.root.after(0, lambda: messagebox.showwarning("Warning", "Please select a private key"))
                            return

                        encryptor = RSAEncryptor()
                        encryptor.decrypt_file(
                            input_path, output_path,
                            private_key_path=private_key
                        )
                    else:
                        raise ValueError("Unknown file format")

                    size = format_size(output_path.stat().st_size)
                    self.root.after(0, lambda: self._log(f"✓ Decrypted: {output_path}"))
                    self.root.after(0, lambda: self._log(f"✓ Size: {size}"))
                    self.root.after(0, lambda: messagebox.showinfo("Success", "File decrypted successfully!"))

                except Exception as e:
                    self.root.after(0, lambda: self._log(f"✗ Error: {e}"))
                    self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                finally:
                    self.root.after(0, self.progress.stop)

            threading.Thread(target=decrypt, daemon=True).start()

        except Exception as e:
            self.progress.stop()
            self._log(f"✗ Error: {e}")
            messagebox.showerror("Error", str(e))

    def _log(self, message: str) -> None:
        """Add a message to the log."""
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def run(self) -> None:
        """Start the GUI main loop."""
        self._log("crypto-tool GUI ready")
        self._log("Select a file to encrypt or decrypt")
        self.root.mainloop()


def main():
    """Entry point for the GUI."""
    if not TKINTER_AVAILABLE:
        print("Error: tkinter is not available")
        print("Please install Python with tkinter support")
        sys.exit(1)

    app = CryptoToolGUI()
    app.run()


if __name__ == "__main__":
    main()
