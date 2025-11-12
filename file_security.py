import os
from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
CIPHER = Fernet(KEY)

PERMISSIONS = {
    "admin": ["read", "write", "delete", "share", "metadata", "encrypt", "decrypt"],
    "user": ["read", "write", "share", "metadata", "encrypt", "decrypt"]
}

def has_permission(role, action):
    return action in PERMISSIONS.get(role, [])

def is_safe_file(filepath, max_size_mb=10):
    try:
        size = os.path.getsize(filepath)
        return size <= max_size_mb * 1024 * 1024
    except Exception:
        return False

def get_metadata(filepath):
    try:
        stat = os.stat(filepath)
        return {
            "size": stat.st_size,
            "owner": stat.st_uid,
            "last_modified": stat.st_mtime
        }
    except Exception as e:
        return str(e)

def encrypt_file(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        encrypted = CIPHER.encrypt(data)
        with open(filepath + ".enc", "wb") as ef:
            ef.write(encrypted)
        return "File encrypted!"
    except Exception as e:
        return f"Encryption failed: {e}"

def decrypt_file(encpath):
    try:
        with open(encpath, "rb") as ef:
            data = ef.read()
        decrypted = CIPHER.decrypt(data)
        with open(encpath.replace(".enc", ""), "wb") as f:
            f.write(decrypted)
        return "File decrypted!"
    except Exception as e:
        return f"Decryption failed: {e}"
