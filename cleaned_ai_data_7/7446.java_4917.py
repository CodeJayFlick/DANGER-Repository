import io
import zlib
from typing import List

class ZLIB:
    ZLIB_ COMPRESSION_NO_LOW = bytes([0x78, 0x01])
    ZLIB_ COMPRESSION_DEFAULT = bytes([0x78, 0x9c])
    ZLIB_ COMPRESSION_BEST = bytes([0x78, 0xda])

    def __init__(self):
        pass

    @staticmethod
    def decompress(compressed_in: io.BytesIO, expected_decompressed_length: int) -> io.BytesIO:
        return self.decompress(compressed_in, expected_decompressed_length, False)

    @staticmethod
    def decompress(compressed_in: io.BytesIO, expected_decompressed_length: int, no_wrap: bool) -> io.BytesIO:
        compressed_bytes = bytes(compressed_in.read())
        
        decompressed_bos = io.BytesIO()
        temp_decompressed_bytes = bytearray(0x10000)
        total_decompressed = 0
        offset = 0

        try:
            while offset < len(compressed_bytes) and total_decompressed < expected_decompressed_length:
                if not no_wrap and compressed_bytes[offset] != 0x78:
                    break
                
                inflater = zlib.Inflater(no_wrap)
                inflater.set_input(compressed_bytes, offset, len(compressed_bytes) - offset)
                
                n_decompressed = inflater.inflate(temp_decompressed_bytes)
                
                if n_decompressed == 0:
                    break

                total_decompressed += n_decompressed
                decompressed_bos.write(temp_decompressed_bytes[:n_decompressed])
                
                offset += inflater.get_total_in()
        except zlib.DataFormatException as e:
            raise io.IOException(e.message)

        return decompressed_bos

    @staticmethod
    def convert_input_stream_to_byte_array(compressed_in: io.BytesIO) -> bytes:
        compressed_bos = io.BytesIO()
        
        while True:
            n_read = compressed_in.read(8096)
            
            if not n_read:
                break
            
            compressed_bos.write(n_read)

        return compressed_bos.getvalue()

    @staticmethod
    def compress(no_wrap: bool, decompressed_bytes: bytes) -> io.BytesIO:
        compressed_bos = io.BytesIO()
        
        temp_buffer = bytearray(0x10000)
        offset = 0
        
        while offset < len(decompressed_bytes):
            deflater = zlib.Deflater(0, no_wrap)
            
            deflater.set_input(decompressed_bytes, offset, len(decompressed_bytes) - offset)
            
            if not deflater.needs_input():
                break
            
            n_deflated = deflater.deflate(temp_buffer)
            
            if n_deflated == 0:
                break

            compressed_bos.write(temp_buffer[:n_deflated])
            
            offset += deflater.get_total_in()

        return compressed_bos

    @staticmethod
    def is_zlib(provider: io.ByteProvider) -> bool:
        try:
            bytes = provider.read_bytes(2)
            
            if bytes == ZLIB_ COMPRESSION_NO_LOW or bytes == ZLIB_ COMPRESSION_DEFAULT or bytes == ZLIB_ COMPRESSION_BEST:
                return True
        except Exception as e:
            pass
        
        return False

