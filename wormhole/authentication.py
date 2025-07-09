from pathlib import Path
import asyncio
import hashlib
import re
import secrets

# This must match the REALM in auth_manager.py
REALM = "Wormhole Proxy"
HASH_ALGORITHM = hashlib.sha256

# Caches for performance
_auth_file_cache: dict = {}
_auth_file_mtime: float = 0.0


def get_ident(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    user: str | None = None,
) -> dict[str, str]:
    """Generates a unique identifier dictionary for a client connection."""
    peername = writer.get_extra_info("peername")
    client_ip = peername[0] if peername else "unknown"
    client_id = f"{user}@{client_ip}" if user else client_ip
    return {"id": hex(id(reader))[-6:], "client": client_id}


def _load_auth_file(path: Path) -> dict | None:
    """Loads and caches the auth file if it has been modified."""
    global _auth_file_cache, _auth_file_mtime
    try:
        current_mtime = path.stat().st_mtime
        if current_mtime > _auth_file_mtime:
            users = {}
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        user, realm, hash_val = line.strip().split(":", 2)
                        users[user] = {"realm": realm, "hash": hash_val}
                    except ValueError:
                        continue  # Ignore malformed lines
            _auth_file_cache = users
            _auth_file_mtime = current_mtime
    except FileNotFoundError:
        return None
    return _auth_file_cache


def _parse_digest_header(header_value: str) -> dict[str, str]:
    """Parses the Digest authentication header into a dictionary."""
    # This regex handles quoted and unquoted values
    parts = re.findall(r'(\w+)=(?:"([^"]*)"|([^\s,]*))', header_value)
    # The regex produces tuples like ('key', 'quoted_val', ''), so we merge
    return {key: val1 or val2 for key, val1, val2 in parts}


async def send_auth_required_response(writer: asyncio.StreamWriter) -> None:
    """Sends a 407 Proxy Authentication Required with a new SHA-256 Digest challenge."""
    nonce = secrets.token_hex(16)
    opaque = secrets.token_hex(16)
    # qop="auth" means quality of protection is authentication.
    challenge = (
        f'Digest realm="{REALM}", '
        f'qop="auth", '
        f"algorithm=SHA-256, "
        f'nonce="{nonce}", '
        f'opaque="{opaque}"'
    )
    response_header = (
        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
        b"Proxy-Authenticate: %s\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ) % challenge.encode("ascii")
    writer.write(response_header)
    await writer.drain()


async def verify_credentials(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    method: str,  # HTTP Method (e.g., 'CONNECT') is needed for HA2 calculation
    uri: str,  # The original URI from the request line
    headers: list[str],
    auth_file_path: str,
) -> dict[str, str] | None:
    """Verifies credentials using manual Digest SHA-256 validation."""
    auth_header_full = next(
        (h for h in headers if h.lower().startswith("proxy-authorization:")),
        None,
    )

    # 1. Check if an auth file exists; if not, deny all
    users = _load_auth_file(Path(auth_file_path))
    if users is None:
        await send_auth_required_response(writer)
        return None

    # 2. Check if the browser sent an Authorization header
    if not auth_header_full:
        await send_auth_required_response(writer)
        return None

    try:
        auth_header_val = auth_header_full.split(" ", 1)[1]
        params = _parse_digest_header(auth_header_val)
        username = params["username"]

        # 3. Look up the user and their stored HA1 hash
        user_data = users.get(username)
        if not user_data:
            await send_auth_required_response(writer)
            return None
        ha1 = user_data["hash"]

        # 4. Calculate HA2 on the server using the URI *from the auth header*
        # --- THIS IS THE FIX ---
        ha2_data = f"{method}:{params['uri']}".encode("utf-8")
        ha2 = HASH_ALGORITHM(ha2_data).hexdigest()

        # 5. Calculate the expected response hash
        response_data = (
            f'{ha1}:{params["nonce"]}:{params["nc"]}:{params["cnonce"]}:'
            f'{params["qop"]}:{ha2}'
        ).encode("utf-8")
        valid_response = HASH_ALGORITHM(response_data).hexdigest()

        # 6. Compare the client's response with our calculated one
        if secrets.compare_digest(valid_response, params["response"]):
            # Success!
            return get_ident(reader, writer, user=username)

    except (KeyError, IndexError):
        # This catches malformed headers or missing parameters
        pass

    # If anything fails, issue a new challenge and deny the request
    await send_auth_required_response(writer)
    return None
