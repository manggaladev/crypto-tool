# 🔐 crypto-tool

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)](https://github.com/manggaladev/crypto-tool)

A file encryptor/decryptor CLI tool using AES-256-GCM and RSA hybrid encryption.

## ✨ Features

- **AES-256-GCM Encryption**: Password-based file encryption with authenticated encryption
- **RSA Hybrid Encryption**: Public/private key encryption for secure file sharing
- **Digital Signatures**: Sign and verify files using RSA keys
- **Folder Encryption**: Encrypt entire folders into a single encrypted archive
- **CLI & GUI**: Both command-line and graphical user interfaces available

## 🔒 Security Features

- **AES-256-GCM**: Authenticated encryption with AES-256 in GCM mode
- **PBKDF2 Key Derivation**: 100,000 iterations with SHA-256 for password-based keys
- **Random Salt & IV**: Each encryption uses a unique salt and initialization vector
- **RSA-OAEP**: Optimal Asymmetric Encryption Padding for RSA encryption
- **Hybrid Encryption**: RSA encrypts a random AES key, AES encrypts the file

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/manggaladev/crypto-tool.git
cd crypto-tool

# Install dependencies
pip install -r requirements.txt

# Or install as package
pip install -e .
```

## 🚀 Usage

### CLI

```bash
# Encrypt a file with password
crypto-tool encrypt-file input.txt output.enc --password mypassword

# Decrypt a file
crypto-tool decrypt-file output.enc decrypted.txt --password mypassword

# Generate RSA key pair
crypto-tool generate-keys

# Encrypt with RSA (hybrid)
crypto-tool encrypt-file input.txt output.enc --public-key public.pem

# Decrypt with RSA (hybrid)
crypto-tool decrypt-file output.enc decrypted.txt --private-key private.pem
```

### GUI

```bash
python -m crypto_tool.gui
```

## 📁 Project Structure

```
crypto-tool/
├── crypto_tool/
│   ├── __init__.py
│   ├── cli.py           # CLI interface
│   ├── gui.py           # GUI interface
│   └── encryptors/
│       ├── aes_encryptor.py
│       └── rsa_encryptor.py
├── tests/
├── examples/
├── requirements.txt
├── pyproject.toml
└── README.md
```

## 📄 License

[MIT License](LICENSE)

Updated: Mon Mar 23 16:36:00 UTC 2026
