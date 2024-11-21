Here is the translation of the Java code into Python:

```Python
import socket
import io
from zlib import compressobj, decompressobj

class RemoteOutputBlockStreamHandle:
    def __init__(self, server, block_count, block_size):
        self.server = server
        self.block_count = block_count
        self.block_size = block_size

    @property
    def serialized(self):
        return 1L

    class ClientOutputBlockStream:
        def __init__(self, socket):
            self.socket = socket
            if compressed:
                self.out = io.BytesIO(compressobj().write(b''))
            else:
                self.out = socket.makefile('wb')

        @property
        def block_count(self):
            return RemoteOutputBlockStreamHandle.this.block_count

        @property
        def block_size(self):
            return RemoteOutputBlockStreamHandle.this.block_size

        def close(self):
            if hasattr(self, 'out'):
                self.out.close()
            self.socket.close()

        def write_block(self, buffer_file_block):
            if not self.blocks_remaining:
                raise EOFError("unexpected data in stream")
            self.out.write(buffer_file_block.to_bytes())
            if --self.blocks_remaining == 0:
                # done with compressed stream, force compressed data to flush
                if hasattr(self, 'out') and isinstance(self.out, io.BytesIO):
                    ((io.BytesIO)(self.out)).flush()
                # perform final handshake after final write
                self.write_stream_end(self.socket)
                self.read_stream_end(self.socket, False)

        def __init__(this, server, block_count, block_size):
            super().__init__(server, block_count, block_size)

    @property
    def blocks_remaining(this):
        return this.block_count

    def open_block_stream(self):
        socket = self.connect()
        socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, this.get_preferred_buffer_size())
        return ClientOutputBlockStream(socket)

    def serve_block_stream(self, socket, block_stream):
        if not isinstance(block_stream, OutputBlockStream):
            raise ValueError("expected OutputBlockStream")
        socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.get_preferred_buffer_size())
        output_block_stream = cast(OutputBlockStream, block_stream)
        try:
            with io.BytesIO() as in_file:
                copy_block_data(output_block_stream, in_file)
            # perform final handshake (uncompressed)
            read_stream_end(socket, True)
            # Need to close blockStream while client is waiting for final stream end indicator
            output_block_stream.close()
            write_stream_end(socket)
        except socket.error as e:
            if str(e).startswith("Broken pipe"):
                raise EOFError("unexpected end of stream")
            raise

    def copy_block_data(self, output_block_stream, in_file):
        if self.compressed:
            in_file = io.BytesIO(decompressobj().decompress(in_file.read()))
        block_count = this.block_count
        bytes = bytearray(this.block_size + 4)  # include space for index
        while block_count > 0:
            total = 0
            while total < len(bytes):
                readlen = in_file.readinto(bytes[total:])
                if readlen < 0:
                    raise EOFError("unexpected end of stream")
                total += readlen
            buffer_file_block = BufferFileBlock.from_bytes(bytes)
            output_block_stream.write_block(buffer_file_block)
            block_count -= 1
        if self.compressed and in_file.read() != -1:  # failed to properly exhaust compressed stream
            raise IOError("expected end of compressed stream")

    def __init__(this, server):
        this.server = server

class OutputBlockStream:
    pass

def write_stream_end(socket):
    pass

def read_stream_end(socket, final_handshake):
    pass

# Usage example:

server = RemoteOutputBlockStreamHandle()
block_count = 10
block_size = 1024
compressed = True

handle = server.open_block_stream()

try:
    with handle as client_output_block_stream:
        # write blocks to the stream
        for i in range(block_count):
            buffer_file_block = BufferFileBlock.from_bytes(b'your data')
            client_output_block_stream.write_block(buffer_file_block)
finally:
    if hasattr(handle, 'close'):
        handle.close()
```

Please note that this translation is not perfect and may require some adjustments to work correctly.