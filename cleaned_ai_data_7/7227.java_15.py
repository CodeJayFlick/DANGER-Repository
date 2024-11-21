import io
from typing import Optional

class Decompressor:
    def decompress(self, mode: str, source: bytes, max_decompressed_size: int,
                   monitor: Optional[io.TextIOWrapper] = None) -> bytes:
        if mode == "LZ4":
            return self.decompress_lz4(source, max_decompressed_size, monitor)
        elif mode == "LZ4HC":
            return self.decompress_lz4hc(source, max_decomposed_size, monitor)
        elif mode == "Uncompressed":
            return source  # not compressed
        else:
            raise ValueError("Invalid storage mode")

    def decompress_lz4(self, source: bytes, max_decompressed_size: int,
                       monitor: Optional[io.TextIOWrapper] = None) -> bytes:
        try:
            decompressed_stream = io.BytesIO()
            compressed_stream = io.BytesIO(source)
            file_utilities.copy_stream_to_stream(compressed_stream, decompressed_stream, monitor)
            return decompressed_stream.getvalue()
        except Exception as e:
            raise IOError(str(e))

    def decompress_lz4hc(self, source: bytes, max_decompressed_size: int,
                          monitor: Optional[io.TextIOWrapper] = None) -> bytes:
        try:
            decompressed_stream = io.BytesIO()
            compressed_stream = io.BytesIO(source)
            file_utilities.copy_stream_to_stream(compressed_stream, decompressed_stream, monitor)
            return decompressed_stream.getvalue()
        except Exception as e:
            raise IOError(str(e))
