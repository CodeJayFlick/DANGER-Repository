Here is the translation of the Java code into Python:

```Python
import socket
import struct
import hashlib

class RemoteBlockStreamHandle:
    def __init__(self, server, block_count, block_size):
        self.stream_server_ip = server.get_server_hostname()
        if not server.is_running() or self.stream_server_ip is None:
            raise IOException("block stream server is not running")
        self.stream_server_port = server.get_server_port()
        self.stream_id = server.next_stream_id
        self.authentication_token = get_random()
        self.block_count = block_count
        self.block_size = block_size

    def is_pending(self):
        return self.connection_pending

    def get_stream_id(self):
        return self.stream_id

    def get_authentication_token(self):
        return self.authentication_token

    def get_block_count(self):
        return self.block_count

    def get_block_size(self):
        return self.block_size

    def get_preferred_buffer_size(self):
        return (self.block_size + 4) * 12

    @staticmethod
    def get_random():
        random = SecureRandomFactory.get_secure_random()
        return random.next_long()

    def get_stream_request_header(self):
        header_prefix = "@stream:"
        stream_id_hex = self.stream_id.to_bytes((self.stream_id.bit_length() + 7) // 8, 'big').hex().zfill(16)
        authentication_token_hex = self.authentication_token.to_bytes((self.authentication_token.bit_length() + 7) // 8, 'big').hex().zfill(16)
        header_suffix = "@"
        return f"{header_prefix}{stream_id_hex}{authentication_token_hex}{header_suffix}"

    def get_stream_terminator(self):
        terminator_prefix = "@end:"
        stream_id_hex = self.stream_id.to_bytes((self.stream_id.bit_length() + 7) // 8, 'big').hex().zfill(16)
        authentication_token_hex = self.authentication_token.to_bytes((self.authentication_token.bit_length() + 7) // 8, 'big').hex().zfill(16)
        terminator_suffix = "@"
        return f"{terminator_prefix}{stream_id_hex}{authentication_token_hex}{terminator_suffix}"

    def check_terminator(self, terminator_bytes):
        term = terminator_bytes.decode('utf-8')
        if len(terminator_bytes) != 32:
            raise IOException("invalid terminatorBytes length")
        if not term.startswith("@end:") or not term.endswith("@"):
            raise IOException("invalid block stream terminator")

    @staticmethod
    def parse_stream_request_header(header_bytes):
        head = header_bytes.decode('utf-8')
        if len(header_bytes) != 32:
            raise ValueError("invalid headerBytes length")
        if not head.startswith("@stream:") or not head.endswith("@"):
            raise IOException("invalid block stream header")

        stream_id_hex = head[10:26]
        authentication_token_hex = head[27:-1]

        try:
            stream_id = int(stream_id_hex, 16)
            authentication_token = int(authentication_token_hex, 16)
            return {"stream_id": stream_id, "authentication_token": authentication_token}
        except ValueError as e:
            raise IOException(f"invalid request header stream ID: {stream_id_hex}")

    def connect(self):
        if not self.connection_pending:
            raise IOException("already connected")
        self.connection_pending = False

        socket_factory = SSLSocketFactory.getDefault()
        socket = socket_factory.create_socket(socket.AF_INET, (self.stream_server_ip, self.stream_server_port))

        # TODO: set socket options ?

        out = socket.makefile('wb')
        out.write(self.get_stream_request_header().encode())
        out.flush()

        return socket

    def write_stream_end(self, socket):
        out = socket.makefile('wb')
        out.write(self.get_stream_terminator().encode())
        out.flush()
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.