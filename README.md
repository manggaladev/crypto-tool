<div align="center">

# 🔐 crypto-tool

**A powerful file encryption CLI tool using AES-256-GCM and RSA hybrid encryption**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

</div>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔒 **AES-256-GCM** | Password-based file encryption with authenticated encryption |
| 🔑 **RSA Hybrid** | Public/private key encryption for secure file sharing |
| ✍️ **Digital Signatures** | Sign and verify files using RSA keys |
| 📁 **Folder Encryption** | Encrypt entire folders into a single archive |
| 💻 **CLI & GUI** | Both command-line and graphical interfaces |

## 🚀 Quick Start

```bash
# Clone
cd crypto-tool

# Install
pip install -r requirements.txt

# Encrypt
crypto-tool encrypt-file secret.txt encrypted.bin --password mypassword

# Decrypt
crypto-tool decrypt-file encrypted.bin decrypted.txt --password mypassword
```

## 🔐 Security

- **PBKDF2** - 100,000 iterations for key derivation
- **Random Salt & IV** - Unique for each encryption
- **RSA-OAEP** - Secure asymmetric encryption padding

## 📦 Installation

```bash
pip install -e .
```

## 💻 Usage

### Password-based Encryption

```bash
# Encrypt
crypto-tool encrypt-file input.txt output.enc -p mypassword

# Decrypt
crypto-tool decrypt-file output.enc decrypted.txt -p mypassword
```

### RSA Key Pair

```bash
# Generate keys
crypto-tool generate-keys

# Encrypt with public key
crypto-tool encrypt-file input.txt output.enc --public-key public.pem

# Decrypt with private key
crypto-tool decrypt-file output.enc decrypted.txt --private-key private.pem
```

## 🤝 Contributing

Contributions are welcome! Feel free to submit issues and pull requests.

## 📄 License

[MIT License](LICENSE)

---

<div align="center">

**[⬆ Back to Top](#-crypto-tool)**


</div>
