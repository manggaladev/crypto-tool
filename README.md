# crypto-tool

A file encryptor/decryptor CLI tool using AES-256-GCM and RSA hybrid encryption.

## Features

- **AES-256-GCM Encryption**: Password-based file encryption with authenticated encryption
- **RSA Hybrid Encryption**: Public/private key encryption for secure file sharing
- **Digital Signatures**: Sign and verify files using RSA keys
- **Folder Encryption**: Encrypt entire folders into a single encrypted archive
- **CLI & GUI**: Both command-line and graphical user interfaces available

## Security Features

- **AES-256-GCM**: Authenticated encryption with AES-256 in GCM mode
- **PBKDF2 Key Derivation**: 100,000 iterations with SHA-256 for password-based keys
- **Random Salt & IV**: Each encryption uses a unique salt and initialization vector
- **RSA-OAEP**: Optimal Asymmetric Encryption Padding for RSA encryption
- **Hybrid Encryption**: RSA encrypts a random AES key, AES encrypts the file

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/manggaladev/crypto-tool.git
cd crypto-tool

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Requirements

- Python 3.10 or higher
- cryptography >= 42.0.0
- click >= 8.1.0

## Usage

### CLI Commands

#### Encrypt a File (AES)

```bash
# Encrypt with password
crypto-tool encrypt -i secret.txt -o secret.enc -p mypassword

# Encrypt with password prompt
crypto-tool encrypt -i secret.txt -o secret.enc
```

#### Decrypt a File (AES)

```bash
# Decrypt with password
crypto-tool decrypt -i secret.enc -o secret.txt -p mypassword

# Decrypt with password prompt
crypto-tool decrypt -i secret.enc -o secret.txt
```

#### Generate RSA Key Pair

```bash
# Generate 2048-bit RSA key pair
crypto-tool generate-key -o ./keys -n mykey

# Generate 4096-bit RSA key pair with password protection
crypto-tool generate-key -o ./keys -n mykey -s 4096 -p mypassword
```

#### Encrypt with RSA (Public Key)

```bash
# Encrypt with RSA public key
crypto-tool encrypt -i secret.txt -o secret.enc -k public.pem -a rsa
```

#### Decrypt with RSA (Private Key)

```bash
# Decrypt with RSA private key
crypto-tool decrypt -i secret.enc -o secret.txt -k private.pem
```

#### Encrypt a Folder

```bash
# Encrypt entire folder
crypto-tool encrypt-folder -i ./documents -o documents.enc
```

#### Decrypt a Folder

```bash
# Decrypt folder archive
crypto-tool decrypt-folder -i documents.enc -o ./documents
```

#### Sign a File

```bash
# Create digital signature
crypto-tool sign -i document.pdf -k private.pem -o document.pdf.sig
```

#### Verify a Signature

```bash
# Verify digital signature
crypto-tool verify -i document.pdf -s document.pdf.sig -k public.pem
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-i, --input` | Input file or folder path |
| `-o, --output` | Output file or folder path |
| `-p, --password` | Password for AES encryption/decryption |
| `-k, --public-key` | Public key file for RSA encryption |
| `-k, --private-key` | Private key file for RSA decryption |
| `-a, --algorithm` | Algorithm: `aes` or `rsa` (default: aes) |
| `-f, --force` | Overwrite existing files |
| `-s, --size` | RSA key size in bits (default: 2048) |
| `-n, --name` | Base name for generated keys |

### GUI

Launch the graphical interface:

```bash
python -m crypto_tool.gui
```

Or run directly:

```bash
python crypto_tool/gui.py
```

### Python API

```python
from crypto_tool import AESEncryptor, RSAEncryptor, generate_key_pair

# AES Encryption
encryptor = AESEncryptor()
encryptor.encrypt_file("secret.txt", "secret.enc", "mypassword")
encryptor.decrypt_file("secret.enc", "secret.txt", "mypassword")

# In-memory encryption
data = b"Secret message"
encrypted = encryptor.encrypt_data(data, "mypassword")
decrypted = encryptor.decrypt_data(encrypted, "mypassword")

# RSA Key Generation
private_key, public_key = generate_key_pair(
    private_key_path="private.pem",
    public_key_path="public.pem",
    key_size=2048,
    password="optional_password"  # Optional
)

# RSA Encryption
rsa = RSAEncryptor()
rsa.encrypt_file("secret.txt", "secret.enc", public_key_path="public.pem")
rsa.decrypt_file("secret.enc", "secret.txt", private_key_path="private.pem")
```

## File Format

### AES Encrypted File

```
+--------+--------+--------+--------+--------+------------+
| MAGIC  | VERSION| SALT   | IV     | TAG    | CIPHERTEXT |
| 4 bytes| 2 bytes| 16 bytes| 12 bytes| 16 bytes| variable   |
+--------+--------+--------+--------+--------+------------+
```

- **MAGIC**: `CRYP` (4 bytes)
- **VERSION**: `0x0100` (2 bytes)
- **SALT**: Random salt for PBKDF2 (16 bytes)
- **IV**: Initialization vector for AES-GCM (12 bytes)
- **CIPHERTEXT**: Encrypted data with authentication tag appended

### RSA Encrypted File

```
+--------+--------+----------+--------------+--------+------------+
| MAGIC  | VERSION| KEY_LEN  | ENCRYPTED_KEY| IV     | CIPHERTEXT |
| 4 bytes| 2 bytes| 4 bytes  | variable     | 12 bytes| variable   |
+--------+--------+----------+--------------+--------+------------+
```

- **MAGIC**: `RRSA` (4 bytes)
- **VERSION**: `0x0100` (2 bytes)
- **KEY_LEN**: Length of encrypted AES key (4 bytes)
- **ENCRYPTED_KEY**: RSA-encrypted AES key
- **IV**: Initialization vector for AES-GCM (12 bytes)
- **CIPHERTEXT**: AES-GCM encrypted data with tag

## Security Considerations

### Best Practices

1. **Strong Passwords**: Use strong, unique passwords for AES encryption
2. **Key Management**: Store private keys securely and protect them with passwords
3. **Key Size**: Use RSA-2048 or higher for adequate security
4. **Password Iterations**: PBKDF2 uses 100,000 iterations by default

### Limitations

- **Memory Usage**: Large files are loaded entirely into memory
- **No Streaming**: Current implementation doesn't support streaming encryption
- **Python Security**: Python's garbage collector may retain sensitive data in memory

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=crypto_tool

# Run specific test file
pytest tests/test_aes.py
```

### Project Structure

```
crypto-tool/
├── crypto_tool/
│   ├── __init__.py
│   ├── cli.py           # CLI commands
│   ├── gui.py           # GUI interface
│   ├── constants.py     # Constants and error messages
│   ├── encryptors/
│   │   ├── __init__.py
│   │   ├── base.py      # Base encryptor class
│   │   ├── aes_encryptor.py
│   │   └── rsa_encryptor.py
│   └── utils/
│       ├── __init__.py
│       ├── file_utils.py
│       ├── key_utils.py
│       └── crypto_utils.py
├── tests/
│   ├── test_aes.py
│   ├── test_rsa.py
│   └── test_cli.py
├── examples/
├── pyproject.toml
├── requirements.txt
└── README.md
```

## License

MIT License - Copyright (c) 2026 manggaladev

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [cryptography](https://cryptography.io/) - Python cryptographic library
- [click](https://click.palletsprojects.com/) - Command Line Interface Creation Kit
