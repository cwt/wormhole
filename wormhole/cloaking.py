import asyncio
import random
from string import ascii_letters, ascii_uppercase, digits


def generate_random_headers():

    def generate_rndstrs(strings, length):
        return ''.join(random.choice(strings) for _ in range(length))

    return (
        'X-%s: %s\r\n' % (
            generate_rndstrs(ascii_uppercase, 16),
            generate_rndstrs(ascii_letters + digits, 128)
        ) for _ in range(32)
    )


async def cloak(req_writer, phost, loop):
    # Add random header lines.
    [req_writer.write(header.encode()) for header in generate_random_headers()]
    await req_writer.drain()

    # Slicing "Host:" line to multiple payloads randomly.
    req_writer.write(b'Host: ')
    await req_writer.drain()

    def feed_phost(phost):
        i = 1
        while phost:
            yield random.randrange(2, 4), phost[:i]
            phost = phost[i:]
            i = random.randrange(2, 5)

    for delay, c in feed_phost(phost):
        await asyncio.sleep(delay / 10.0, loop=loop)
        req_writer.write(c.encode())
        await req_writer.drain()
