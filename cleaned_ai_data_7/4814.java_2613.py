class DyldCacheLocalSymbolsEntry:
    def __init__(self):
        self.dylib_offset = None
        self.nlist_start_index = None
        self.nlist_count = None

    @classmethod
    def from_binary_reader(cls, reader):
        try:
            dylib_offset = int.from_bytes(reader.read(4), 'little')
            nlist_start_index = int.from_bytes(reader.read(4), 'little')
            nlist_count = int.from_bytes(reader.read(4), 'little')
            return cls(dylib_offset, nlist_start_index, nlist_count)
        except Exception as e:
            raise IOError("Error reading from binary reader") from e

    def to_data_type(self):
        try:
            struct = {'name': "dyld_cache_local_symbols_entry", 
                      'fields': [
                          {"name": "dylibOffset", "type": int, "offset": 0},
                          {"name": "nlistStartIndex", "type": int, "offset": 4},
                          {"name": "nlistCount", "type": int, "offset": 8}
                      ]
            }
        except Exception as e:
            raise DuplicateNameException("Error creating data type") from e
