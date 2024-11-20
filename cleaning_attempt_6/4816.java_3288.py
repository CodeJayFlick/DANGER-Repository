class DyldCacheMappingInfo:
    def __init__(self):
        self.address = 0
        self.size = 0
        self.file_offset = 0
        self.max_prot = 0
        self.init_prot = 0

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = value

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        self._size = value

    @property
    def file_offset(self):
        return self._file_offset

    @file_offset.setter
    def file_offset(self, value):
        self._file_offset = value

    @property
    def max_prot(self):
        return self._max_prot

    @max_prot.setter
    def max_prot(self, value):
        self._max_prot = value

    @property
    def init_prot(self):
        return self._init_prot

    @init_prot.setter
    def init_prot(self, value):
        self._init_prot = value

    def __str__(self):
        return f"Address: {self.address}, Size: {self.size}, File Offset: {self.file_offset}, Max Prot: {self.max_prot}, Init Prot: {self.init_prot}"

class BinaryReader:
    def read_next_long(self, reader):
        # This method should be implemented based on the actual binary file
        pass

def main():
    reader = BinaryReader()
    dyld_cache_mapping_info = DyldCacheMappingInfo()

    try:
        dyld_cache_mapping_info.address = reader.read_next_long(reader)
        dyld_cache_mapping_info.size = reader.read_next_long(reader)
        dyld_cache_mapping_info.file_offset = reader.read_next_long(reader)
        dyld_cache_mapping_info.max_prot = reader.read_next_int()
        dyld_cache_mapping_info.init_prot = reader.read_next_int()

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
