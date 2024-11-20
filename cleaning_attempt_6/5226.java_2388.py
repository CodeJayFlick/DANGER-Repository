class MemoryByteProvider:
    def __init__(self, memory, base_address=None):
        self.memory = memory
        if base_address is None:
            self.base_address = 0
        else:
            self.base_address = base_address

    def get_address(self, index):
        return self.base_address + index

    def get_input_stream(self, index):
        return MemoryByteProviderInputStream(self.memory, self.get_address(index))

    @property
    def file_path(self):
        return self.memory.program.executable_path()

    @property
    def name(self):
        return self.memory.program.name

    @property
    def absolute_path(self):
        return self.file_path

    def length(self):
        block = self.memory.block_at_address(self.base_address)
        if block is None or not block.is_initialized():
            return 0
        else:
            return (block.end - self.base_address) + 1

    def is_valid_index(self, index):
        try:
            address = self.get_address(index)
            return self.memory.contains(address)
        except Exception as e:
            return False

    def read_byte(self, index):
        try:
            return self.memory.read_byte(self.get_address(index))
        except Exception as e:
            raise IOError(str(e))

    def read_bytes(self, index, length):
        bytes = bytearray(length)
        n_read = self.memory.read_bytes(self.get_address(index), bytes)
        if n_read != length:
            raise IOError(f"Unable to read {length} bytes at index {index}")
        return bytes

class MemoryByteProviderInputStream:
    def __init__(self, memory, address):
        self.memory = memory
        self.address = address

    def read(self, size):
        try:
            data = bytearray(size)
            n_read = self.memory.read_bytes(self.address, data)
            if n_read != size:
                raise IOError("Unable to read bytes")
            return data[:n_read]
        except Exception as e:
            raise IOError(str(e))
