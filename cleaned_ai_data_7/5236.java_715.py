class StructConverter:
    BYTE = "BYTE"
    WORD = "WORD"
    DWORD = "DWORD"
    QWORD = "QWORD"
    ASCII = "ASCII"
    STRING = "STRING"
    UTF8 = "UTF8"
    UTF16 = "UTF16"
    POINTER = "POINTER"
    VOID = "VOID"

    IBO32 = {"name": "IBO32", "size": 4}
    IBO64 = {"name": "IBO64", "size": 8}

    def to_data_type(self):
        # This method should be implemented based on the actual class members
        pass

# Example usage:
converter = StructConverter()
print(converter.BYTE)  # Output: BYTE
