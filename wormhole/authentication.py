from base64 import decodebytes


def get_ident(client_reader, client_writer, user=None):
    client = client_writer.get_extra_info('peername')[0]
    if user:
        client = '%s@%s' % (user, client)
    return {'id': hex(id(client_reader))[-6:], 'client':client}


auth_list = list()
def get_auth_list(auth):
    global auth_list
    if not auth_list:
        auth_list = [line.strip()
                     for line in open(auth, 'r')
                     if line.strip() and not line.strip().startswith('#')]
    return auth_list


def deny(client_writer):
    [client_writer.write(message)
     for message in (
         b'HTTP/1.1 407 Proxy Authentication Required\r\n',
         b'Proxy-Authenticate: Basic realm="Wormhole Proxy"\r\n',
         b'\r\n'
     )]


async def verify(client_reader, client_writer, headers, auth):
    proxy_auth = [header for header in headers
                  if header.lower().startswith('proxy-authorization:')]
    if proxy_auth:
        user_password = decodebytes(
            proxy_auth[0].split(' ')[2].encode('ascii')
        ).decode('ascii')
        if user_password in get_auth_list(auth):
            user = user_password.split(':')[0]
            return get_ident(client_reader, client_writer, user)
    return deny(client_writer)
