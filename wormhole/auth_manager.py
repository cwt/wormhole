from pathlib import Path
import getpass
import hashlib
import os
import stat
import sys

REALM = "Wormhole Proxy"
HASH_ALGORITHM = hashlib.sha256  # Use SHA-256


def _get_password_confirm() -> str | None:
    """Gets and confirms a new password from the user."""
    try:
        p1 = getpass.getpass()
        p2 = getpass.getpass("Retype password: ")
        if p1 != p2:
            print("Passwords do not match.", file=sys.stderr)
            return None
        return p1
    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.", file=sys.stderr)
        return None


def _secure_create_file(path: Path) -> bool:
    """Creates a file with secure permissions (0600) and a warning for unsupported filesystems."""
    if sys.platform == "win32":
        # On Windows, we rely on default user permissions and warn if the filesystem is not NTFS.
        try:
            import win32api

            fs_type = win32api.GetVolumeInformation(
                str(path.resolve().drive) + "\\"
            )[4]
            if fs_type.upper() != "NTFS":
                print(
                    "Warning: Filesystem is not NTFS. File permissions may not be secure.",
                    file=sys.stderr,
                )
        except (ImportError, Exception):
            print(
                "Warning: Could not determine filesystem type. Ensure the auth file is stored securely.",
                file=sys.stderr,
            )
        path.touch()
        return True
    else:
        # On POSIX, create with 0600 permissions.
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_WRONLY, mode=0o600)
            os.close(fd)
            if stat.S_IMODE(os.stat(path).st_mode) != 0o600:
                print(
                    "Warning: Filesystem may not support secure permissions (0600).",
                    file=sys.stderr,
                )
            return True
        except OSError as e:
            print(f"Error creating secure file: {e}", file=sys.stderr)
            return False


def _read_auth_file(path: Path) -> dict:
    """Reads the auth file into a dictionary."""
    users = {}
    if path.is_file():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    user, realm, hash_val = line.strip().split(":", 2)
                    users[user] = {"realm": realm, "hash": hash_val}
                except ValueError:
                    continue  # Ignore malformed lines
    return users


def _write_auth_file(path: Path, users: dict) -> None:
    """Writes the dictionary back to the auth file."""
    with open(path, "w", encoding="utf-8") as f:
        for user, data in users.items():
            f.write(f"{user}:{data['realm']}:{data['hash']}\n")


def add_user(auth_file_str: str, username: str) -> int:
    """Adds a new user to the specified digest file."""
    auth_path = Path(auth_file_str)
    if not auth_path.exists():
        if not _secure_create_file(auth_path):
            return 1

    users = _read_auth_file(auth_path)
    if username in users:
        print(
            f"Error: User '{username}' already exists. Use --auth-mod to change password.",
            file=sys.stderr,
        )
        return 1

    print(f"Adding user '{username}' to {auth_file_str}")
    print("Enter new password:")
    password = _get_password_confirm()
    if not password:
        return 1

    # Calculate HA1 = HASH(username:realm:password)
    ha1_data = f"{username}:{REALM}:{password}".encode("utf-8")
    ha1 = HASH_ALGORITHM(ha1_data).hexdigest()

    users[username] = {"realm": REALM, "hash": ha1}
    _write_auth_file(auth_path, users)
    print(f"Successfully added user '{username}'.")
    return 0


def modify_user(auth_file_str: str, username: str) -> int:
    """Modifies an existing user's password."""
    auth_path = Path(auth_file_str)
    if not auth_path.is_file():
        print(
            f"Error: Authentication file not found at '{auth_file_str}'",
            file=sys.stderr,
        )
        return 1

    users = _read_auth_file(auth_path)
    if username not in users:
        print(
            f"Error: User '{username}' not found. Use --auth-add to create it.",
            file=sys.stderr,
        )
        return 1

    print(f"Changing password for user '{username}'")
    print("Enter new password:")
    password = _get_password_confirm()
    if not password:
        return 1

    ha1_data = f"{username}:{REALM}:{password}".encode("utf-8")
    ha1 = HASH_ALGORITHM(ha1_data).hexdigest()
    users[username]["hash"] = ha1
    _write_auth_file(auth_path, users)
    print(f"Successfully changed password for user '{username}'.")
    return 0


def delete_user(auth_file_str: str, username: str) -> int:
    """Deletes a user from the specified digest file."""
    auth_path = Path(auth_file_str)
    if not auth_path.is_file():
        print(
            f"Error: Authentication file not found at '{auth_file_str}'",
            file=sys.stderr,
        )
        return 1

    users = _read_auth_file(auth_path)
    if username not in users:
        print(f"Error: User '{username}' not found.", file=sys.stderr)
        return 1

    del users[username]
    _write_auth_file(auth_path, users)
    print(f"Successfully deleted user '{username}'.")
    return 0
