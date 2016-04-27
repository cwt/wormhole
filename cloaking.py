"""
Copyright (c) 2016 cwt
Copyright (c) 2013 devunt

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
"""

import asyncio
import random
from string import ascii_letters, ascii_uppercase, digits

def generate_random_headers():

    def generate_rndstrs(strings, length):
        return ''.join(random.choice(strings) for _ in range(length))

    return ['X-%s: %s\r\n' % (
        generate_rndstrs(ascii_uppercase, 16),
        generate_rndstrs(ascii_letters + digits, 128)
    ) for _ in range(32)]

async def cloak(req_writer, phost, loop):
    # Add random header lines.
    req_writer.writelines(
        list(map(lambda x: x.encode(), generate_random_headers())))
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
