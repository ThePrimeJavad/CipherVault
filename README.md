🔐 CipherVault

CipherVault is a secure folder encryption tool for Python. It encrypts file contents, filenames, and even password files, making them safe to store or transfer. Original files are replaced during the process.

⚙️ Features

🔒 Encrypt and decrypt entire folders

📝 Preserve filenames in encrypted form

🛡️ Encrypt sensitive password files for safe transport

🔑 Password-based key derivation with scrypt

👀 Dry-run mode to preview changes without touching files

🗄️ Automatic salt management for consistent encryption

🛠️ Requirements
pip install cryptography

🚀 Usage
python ciphervault.py <encrypt|decrypt> <folder> [--salt-file SALT_FILE] [--dry-run]


Examples:

# 🔒 Encrypt a folder
python ciphervault.py encrypt /path/to/folder

# 🔓 Decrypt a folder
python ciphervault.py decrypt /path/to/folder

# 👀 Dry-run to list files only
python ciphervault.py encrypt /path/to/folder --dry-run

⚠️ Notes

This tool is destructive: it replaces original files with encrypted versions.

Password-protected files can be safely moved or stored after encryption.

Always back up important data before encrypting.

Salt file ensures consistent encryption across sessions (default: .crypto_salt).

💡 Recommended Use

Use CipherVault for personal file encryption, secure folder storage, password file protection, or simple password-protected backups. Lightweight, dependency-free except for cryptography, and cross-platform.