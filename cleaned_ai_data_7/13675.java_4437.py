import io
from zlib import compress as zcompress, decompress as zdecompress


class ZLIB:
    def __init__(self):
        pass

    def decompress(self, compressed_in: bytes, expected_decompressed_length: int) -> bytearray:
        return self.decompress(compressed_in, expected_decompressed_length, False)

    def decompress(self, compressed_in: bytes, expected_decompressed_length: int, no_wrap: bool) -> bytearray:
        compressed_bytes = io.BytesIO(compressed_in)
        decompressed_bos = io.BytesIO()
        temp_decompressed_bytes = bytearray(0x10000)

        total_decompressed = 0
        offset = 0

        try:
            while offset < len(compressed_bytes.getvalue()) and total_decompressed < expected_decompressed_length:
                if not no_wrap and compressed_bytes.read(1) != b'\x78':
                    break

                inflater = io.BytesIO()
                inflater.write(compressed_bytes.read(len(compressed_bytes.getvalue()) - offset))
                inflater.seek(0)

                n_decompressed, remaining = zlib.inflate(inflater.read(len(temp_decompressed_bytes)), temp_decompressed_bytes)
                if not n_decompressed:
                    break
                total_decompressed += n_decompressed

                decompressed_bos.write(temp_decompressed_bytes[:n_decompressed])
                offset += len(compressed_bytes.getvalue()) - inflater.tell()
        except Exception as e:
            raise io.IOError(str(e))

        return decompressed_bos.getvalue()

    def compress(self, no_wrap: bool = False, decompressed_bytes: bytes = b'') -> bytearray:
        compressed_bos = io.BytesIO()
        temp_buffer = bytearray(0x10000)
        offset = 0

        while offset < len(decompressed_bytes):
            deflater = io.BytesIO()
            deflater.write(decompressed_bytes[offset:])
            deflater.seek(0)

            n_deflated, remaining = zlib.deflate(deflater.read(len(temp_buffer)), temp_buffer)
            if not n_deflated:
                break
            compressed_bos.write(temp_buffer[:n_deflated])
            offset += len(compressed_bytes.getvalue()) - deflater.tell()

        return compressed_bos.getvalue()

    @staticmethod
    def convert_inputstream_to_bytearray(compressed_in: io.IOBase) -> bytearray:
        bytes = bytearray(8096)
        compressed_bos = io.BytesIO()
        while True:
            n_read, remaining = compressed_in.readinto(bytes)
            if not n_read:
                break
            compressed_bos.write(bytes[:n_read])
        return compressed_bos.getvalue()


# Example usage:
zlib_obj = ZLIB()
compressed_bytes = zlib_obj.compress(b'Hello World!')
decompressed_bytes = zlib_obj.decompress(compressed_bytes, len('Hello World!'))
print(decompressed_bytes.decode())
