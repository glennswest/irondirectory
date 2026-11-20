"""A TLS-terminating relay, for test/ldap-channel-binding-e2e.sh (#65).

  python tls_relay.py <listen-port> <upstream-port> <cert> <key>

Accepts TLS on 127.0.0.1:<listen-port> with its own certificate, opens a
TLS connection to 127.0.0.1:<upstream-port> (not verifying it), and copies
bytes both ways -- what a man in the middle relaying a GSSAPI bind does.
A client's channel bindings then name the relay's certificate, not the
server's. Prints "listening" once ready.
"""

import asyncio
import ssl
import sys

listen_port, upstream_port, cert, key = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]

server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_ctx.load_cert_chain(cert, key)
client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
client_ctx.check_hostname = False
client_ctx.verify_mode = ssl.CERT_NONE


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, ssl.SSLError):
        pass
    finally:
        writer.close()


async def handle(client_reader, client_writer):
    up_reader, up_writer = await asyncio.open_connection("127.0.0.1", upstream_port, ssl=client_ctx)
    await asyncio.gather(pipe(client_reader, up_writer), pipe(up_reader, client_writer))


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", listen_port, ssl=server_ctx)
    print("listening", flush=True)
    async with server:
        await server.serve_forever()


asyncio.run(main())
