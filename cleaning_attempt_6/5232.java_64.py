class ObfuscatedOutputStream:
    def __init__(self, delegate):
        self.delegate = delegate
        self.current_position = 0

    def close(self):
        try:
            self.delegate.close()
        except Exception as e:
            print(f"Error closing stream: {e}")

    def flush(self):
        try:
            self.delegate.flush()
        except Exception as e:
            print(f"Error flushing stream: {e}")

    def write(self, b, off=0, len=None):
        if not isinstance(b, bytes):
            raise TypeError("Input must be a byte string")

        tmp_buffer = bytearray(len)
        for i in range(len):
            byte_index = self.current_position + i
            xor_mask_index = int(byte_index % 256)  # assuming XOR_MASK_BYTES is an array of length 256
            xor_mask = ObfuscatedFileByteProvider.XOR_MASK_Bytes[xor_mask_index]
            tmp_buffer[i] = b[off+i] ^ xor_mask

        self.delegate.write(tmp_buffer)
        self.current_position += len

    def write(self, b):
        if not isinstance(b, int):
            raise TypeError("Input must be an integer")
        self.write([b].to_bytes(1, 'big'))

class ObfuscatedFileByteProvider:
    XOR_MASK_Bytes = [0x12]  # assuming this is the array of length 256

# usage
delegate_stream = open('output.txt', 'wb')
obfuscated_stream = ObfuscatedOutputStream(delegate_stream)
try:
    obfuscated_stream.write(b'Hello, World!', 0, len(b'Hello, World!'))
finally:
    obfuscated_stream.close()
