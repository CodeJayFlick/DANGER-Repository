import io
from typing import Any

class CompressionTypeNotSupportedException(Exception):
    pass


class ICompressor:
    @staticmethod
    def get_compressor(name: str) -> 'ICompressor':
        return ICompressor.get_compressor(CompressionType.valueOf(name))

    @staticmethod
    def get_compressor(compression_type: CompressionType) -> 'ICompressor':
        if compression_type is None:
            raise CompressionTypeNotSupportedException("NULL")

        switcher = {
            CompressionType.UNCOMPRESSED: lambda: NoCompressor(),
            CompressionType.SNAPPY: lambda: SnappyCompressor(),
            CompressionType.LZ4: lambda: IOTDBLZ4Compressor(),
            CompressionType.GZIP: lambda: GZIPCompressor()
        }
        return switcher.get(compression_type, lambda: None)()

    def compress(self, data: bytes) -> bytes:
        raise NotImplementedError

    def compress(self, data: memoryview, compressed: memoryview) -> int:
        raise NotImplementedError

    def get_max_bytes_for_compression(self, uncompressed_data_size: int) -> int:
        raise NotImplementedError

    def get_type(self) -> CompressionType:
        raise NotImplementedError


class NoCompressor(ICompressor):
    def compress(self, data: bytes) -> bytes:
        return data

    def compress(self, data: memoryview, compressed: memoryview) -> int:
        raise ValueError("No Compressor does not support compression function")

    def get_max_bytes_for_compression(self, uncompressed_data_size: int) -> int:
        return uncompressed_data_size

    def get_type(self) -> CompressionType:
        return CompressionType.UNCOMPRESSED


class SnappyCompressor(ICompressor):
    @staticmethod
    def compress(data: bytes) -> bytes:
        if data is None:
            return bytearray()
        return io.BytesIO(Snappy.compress(data)).read()

    def compress(self, data: memoryview, compressed: memoryview) -> int:
        return Snappy.compress(data.tobytes(), 0, len(data), compressed)

    def get_max_bytes_for_compression(self, uncompressed_data_size: int) -> int:
        return Snappy.max_compressed_length(uncompressed_data_size)

    def get_type(self) -> CompressionType:
        return CompressionType.SNAPPY


class IOTDBLZ4Compressor(ICompressor):
    def __init__(self):
        self.compressor = LZ4Factory.fastest_instance().fast_compressor()

    def compress(self, data: bytes) -> bytes:
        if data is None:
            return bytearray()
        return io.BytesIO(self.compressor.compress(data)).read()

    def compress(self, data: memoryview, compressed: memoryview) -> int:
        self.compressor.compress(data.tobytes(), 0, len(data), compressed)

    def get_max_bytes_for_compression(self, uncompressed_data_size: int) -> int:
        return self.compressor.max_compressed_length(uncompressed_data_size)

    def get_type(self) -> CompressionType:
        return CompressionType.LZ4


class GZIPCompress:
    @staticmethod
    def compress(data: bytes) -> bytes:
        out = io.BytesIO()
        with io.GzipFile(mode='wb', fileobj=out) as gzip_file:
            gzip_file.write(data)
        return out.getvalue()

    @staticmethod
    def uncompress(data: bytes) -> bytes:
        in_ = io.BytesIO(data)
        out = io.BytesIO()
        with io.GzipFile(fileobj=in_, mode='rb') as ungzip_file, \
                io.GzipFile(mode='wb', fileobj=out):
            while True:
                chunk = bytearray(256)
                n = ungzip_file.readinto(chunk)
                if not n:
                    break
                out.write(bytearray(chunk[:n]))
        return out.getvalue()


class GZIPCompressor(ICompressor):
    def compress(self, data: bytes) -> bytes:
        if data is None:
            return bytearray()
        return GZIPCompress.compress(data)

    def compress(self, data: memoryview, compressed: memoryview) -> int:
        length = len(data)
        data_before = bytearray(length)
        data.tobytes()[0:length].tobytes().into(data_before)
        res = GZIPCompress.compress(bytearray(data))
        compressed.frombytes(res)
        return len(res)

    def get_max_bytes_for_compression(self, uncompressed_data_size: int) -> int:
        # hard to estimate
        return max(40 + uncompressed_data_size // 2, uncompressed_data_size)

    def get_type(self) -> CompressionType:
        return CompressionType.GZIP


class CompressionType(Enum):
    UNCOMPRESSED = "UNCOMPRESSED"
    SNAPPY = "SNAPPY"
    LZ4 = "LZ4"
    GZIP = "GZIP"


if __name__ == "__main__":
    compressor = ICompressor.get_compressor(CompressionType.SNAPPY)
    data = bytearray(b"Hello, World!")
    compressed_data = bytearray()
    try:
        length = compressor.compress(data, 0, len(data), compressed_data)
    except Exception as e:
        print(f"An error occurred: {e}")
