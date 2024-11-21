class Ext4Extent:
    def __init__(self, provider):
        self.ee_block = 0
        self.ee_len = 0
        self.ee_start_hi = 0
        self.ee_start_lo = 0

        if isinstance(provider, bytes):
            reader = BinaryReader(provider)
        else:
            raise ValueError("Invalid provider type")

        try:
            self.ee_block = int.from_bytes(reader.read(4), 'little')
            self.ee_len = int.from_bytes(reader.read(2), 'little') & 0xFFFF
            self.ee_start_hi = int.from_bytes(reader.read(2), 'little') >> 16
            self.ee_start_lo = int.from_bytes(reader.read(4), 'little')

        except Exception as e:
            print(f"Error: {str(e)}")

    def get_ee_block(self):
        return self.ee_block

    def get_ee_len(self):
        return self.ee_len

    def get_ee_start_hi(self):
        return self.ee_start_hi

    def get_ee_start_lo(self):
        return self.ee_start_lo

    @property
    def extent_block_count(self):
        return 0x10000 | (self.ee_len & 0xFFFF)

    @property
    def stream_block_number(self):
        return int.from_bytes((self.ee_block).to_bytes(4, 'little'), 'little')

    @property
    def extent_start_block_number(self):
        return self.stream_block_number + ((2**32) * (self.ee_start_hi)) | self.ee_start_lo

class BinaryReader:
    def __init__(self, provider):
        if isinstance(provider, bytes):
            self.provider = provider
        else:
            raise ValueError("Invalid provider type")

    def read(self, size):
        return self.provider[:size]

# Example usage:

provider = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
reader = BinaryReader(provider)
extent = Ext4Extent(reader)

print(extent.extent_block_count)  # prints the extent block count
print(extent.stream_block_number)   # prints the stream block number
print(extent.extent_start_block_number)  # prints the start block number of where data for this extent is stored

