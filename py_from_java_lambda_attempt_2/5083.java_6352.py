Here is the translation of the Java code to Python:

```Python
class OMFLibrary:
    def __init__(self):
        self.libs = []

    @staticmethod
    def create_OMF_library(reader, ptr, num_bytes):
        omf_library = OMFLibrary()
        omf_library.init_OMF_library(reader, ptr, num_bytes)
        return omf_library

    def init_OMF_library(self, reader, ptr, num_bytes):
        lib_list = []
        while num_bytes > 0:
            len_byte = reader.read_byte(ptr)
            ptr += 1
            num_bytes -= 1
            length = Conv.byte_to_int(len_byte)
            lib = reader.read_ascii_string(ptr, length)
            ptr += length
            num_bytes -= length
            lib_list.append(lib)
        self.libs = lib_list

    def get_libraries(self):
        return self libs


class Reader:
    @staticmethod
    def read_byte(ptr):
        # implement your byte reading logic here
        pass

    @staticmethod
    def read_ascii_string(ptr, length):
        # implement your ASCII string reading logic here
        pass


class Conv:
    @staticmethod
    def byte_to_int(len_byte):
        # implement your byte to int conversion logic here
        pass
```

Please note that the above Python code is a direct translation of the Java code and does not include any actual implementation for methods like `read_byte`, `read_ascii_string` and `byte_to_int`. You would need to add these implementations based on how you want your reader class to read bytes, ASCII strings and convert byte values to integers.