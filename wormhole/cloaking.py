import asyncio
from random import choice
from random import randint
from string import ascii_letters, ascii_uppercase, digits


def generate_random_string(strings, length):
    return ''.join(choice(strings) for _ in range(length))


def generate_random_headers():
    return (
        'X-%s: %s\r\n' % (
            generate_random_string(ascii_uppercase, randint(4,16)),
            generate_random_string(ascii_letters + digits, randint(32,128))
        ) for _ in range(32)
    )


async def cloak(req_writer, hostname, loop):
    # Add random header lines.
    [req_writer.write(header.encode()) for header in generate_random_headers()]
    await req_writer.drain()

    # Slicing "Host:" line to multiple payloads randomly.
    req_writer.write(b'Host: ')
    await req_writer.drain()

    def feed_host(hostname):
        i = 1
        while hostname:
            yield randint(2, 4), hostname[:i]
            hostname = hostname[i:]
            i = randint(2, 5)

    for delay, c in feed_host(hostname):
        await asyncio.sleep(delay / 10.0, loop=loop)
        req_writer.write(c.encode())
        await req_writer.drain()
