from base64 import decodebytes
import asyncio


def get_ident(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    user: str | None = None,
) -> dict[str, str]:
    client = client_writer.get_extra_info("peername")[0]
    if user:
        client = f"{user}@{client}"
    return {"id": hex(id(client_reader))[-6:], "client": client}


auth_list: list[str] = []


def get_auth_list(auth: str) -> list[str]:
    global auth_list
    if not auth_list:
        with open(auth, "r") as f:

            auth_list = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    return auth_list


async def deny(client_writer: asyncio.StreamWriter) -> None:
    messages = (
        b"HTTP/1.1 407 Proxy Authentication Required\r\n",
        b'Proxy-Authenticate: Basic realm="Wormhole Proxy"\r\n',
        b"\r\n",
    )
    for message in messages:
        client_writer.write(message)
    await client_writer.drain()


async def verify(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    headers: list[str],
    auth: str,
) -> dict[str, str] | None:
    proxy_auth = [h for h in headers if h.lower().startswith("proxy-authorization:")]
    if proxy_auth:

        user_password = decodebytes(proxy_auth[0].split(" ")[2].encode("ascii")).decode(
            "ascii"
        )
        if user_password in get_auth_list(auth):
            return get_ident(client_reader, client_writer, user_password.split(":")[0])
    await deny(client_writer)
    return None
