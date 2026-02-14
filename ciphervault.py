import argparse
import base64
import os
from getpass import getpass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ENCRYPTED_EXTENSION = ".vault"

#Password Generator
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password and salt using scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)

# Salt Loader it will be created if don't exist
def load_or_create_salt(salt_path: Path) -> bytes:
    """Load existing salt or create one if missing."""
    if salt_path.exists():
        return salt_path.read_bytes()

    salt = os.urandom(16)
    salt_path.write_bytes(salt)
    os.chmod(salt_path, 0o600)
    return salt

# encrypt filename function
def encrypt_filename(original_name: str, cipher: Fernet) -> str:
    token = cipher.encrypt(original_name.encode("utf-8")).decode("utf-8")
    return f"{token}{ENCRYPTED_EXTENSION}"

# decrypt filename function
def decrypt_filename(encrypted_name: str, cipher: Fernet) -> str:
    token = encrypted_name[: -len(ENCRYPTED_EXTENSION)]
    decoded = cipher.decrypt(token.encode("utf-8"))
    return decoded.decode("utf-8")

# encrypt file function
def encrypt_file(file_path: Path, cipher: Fernet) -> None:
    if file_path.suffix == ENCRYPTED_EXTENSION:
        return

    encrypted_name = encrypt_filename(file_path.name, cipher)
    encrypted_path = file_path.with_name(encrypted_name)

    data = file_path.read_bytes()
    encrypted_data = cipher.encrypt(data)

    encrypted_path.write_bytes(encrypted_data)

    # Always delete original
    file_path.unlink()

# decrypt file function
def decrypt_file(enc_path: Path, cipher: Fernet) -> None:
    if enc_path.suffix != ENCRYPTED_EXTENSION:
        return

    try:
        original_name = decrypt_filename(enc_path.name, cipher)
        decrypted_data = cipher.decrypt(enc_path.read_bytes())
    except InvalidToken:
        print(f"[WARN] Wrong password or corrupt file skipped: {enc_path}")
        return

    output_path = enc_path.with_name(original_name)
    output_path.write_bytes(decrypted_data)

    # Always delete encrypted file
    enc_path.unlink()


def iter_target_files(root: Path, mode: str, exclude_names: set[str]):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name in exclude_names:
            continue

        if mode == "encrypt" and path.suffix != ENCRYPTED_EXTENSION:
            yield path
        elif mode == "decrypt" and path.suffix == ENCRYPTED_EXTENSION:
            yield path


def process_folder(
    folder: Path,
    mode: str,
    cipher: Fernet,
    dry_run: bool,
    exclude_names: set[str],
) -> None:
    files = list(iter_target_files(folder, mode, exclude_names))
    if not files:
        print("[INFO] No files found to process.")
        return

    print(f"[INFO] {mode.capitalize()}ing {len(files)} files in: {folder}")
    for f in files:
        print(f" - {f}")

    if dry_run:
        print("[INFO] Dry-run mode: no files changed.")
        return

    for f in files:
        if mode == "encrypt":
            encrypt_file(f, cipher)
        else:
            decrypt_file(f, cipher)

    print(f"[OK] {mode.capitalize()}ion complete.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Folder encrypter/decrypter (destructive mode)."
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode.")
    parser.add_argument("folder", type=Path, help="Folder to process.")
    parser.add_argument(
        "--salt-file",
        type=Path,
        default=Path(".crypto_salt"),
        help="Path to salt file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List files only; do not change anything.",
    )

    args = parser.parse_args()

    if not args.folder.exists() or not args.folder.is_dir():
        raise ValueError(f"Folder does not exist or is not a directory: {args.folder}")

    password = getpass("Enter password: ")
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = load_or_create_salt(args.salt_file)
    key = derive_key_from_password(password, salt)
    cipher = Fernet(key)

    exclude_names = {args.salt_file.name}

    process_folder(
        folder=args.folder,
        mode=args.mode,
        cipher=cipher,
        dry_run=args.dry_run,
        exclude_names=exclude_names,
    )


if __name__ == "__main__":
    main()
