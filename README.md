# 🔐 CipherVault

Encrypt folders, filenames, and password files with Python. Original files are replaced.

---

## ⚙️ Features

* 🔒 Encrypt/decrypt folders
* 📝 Preserve filenames
* 🛡️ Encrypt password files for safe transfer
* 🔑 Password-derived keys (scrypt + Fernet)
* 👀 Dry-run preview
* 🗄️ Automatic salt management

---

## 🛠️ Requirements

```bash
Python 3.7+
pip install cryptography
```

---

## 🚀 Usage

```bash
python ciphervault.py <encrypt|decrypt> <folder> [--salt-file SALT_FILE] [--dry-run]
```

### Examples

```bash
# 🔒 Encrypt
python ciphervault.py encrypt /path/to/folder

# 🔓 Decrypt
python ciphervault.py decrypt /path/to/folder

# 👀 Dry-run
python ciphervault.py encrypt /path/to/folder --dry-run
```

---

## ⚠️ Notes

* Destructive: replaces original files
* Encrypted password files are safe to move/store
* Backup important data first
* Salt file default: `.crypto_salt`
