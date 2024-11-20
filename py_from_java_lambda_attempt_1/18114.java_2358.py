Here is the translation of the Java code into Python:

```Python
class TSFileConfig:
    RLE_MIN_REPEATED_NUM = 8
    RLE_MAX_REPEATED_NUM = 0x7FFF
    RLE_MAX_BIT_PACKED_NUM = 63
    
    FLOAT_VALUE_LENGTH = 6
    DOUBLE_VALUE_LENGTH = 7

    VALUE_BITS_LENGTH_32BIT = 32
    LEADING_ZERO_BITS_LENGTH_32BIT = 5
    MEANINGFUL_XOR_BITS_LENGTH_32BIT = 5

    VALUE_BITS_LENGTH_64BIT = 64
    LEADING_ZERO_BITS_LENGTH_64BIT = 6
    MEANINGFUL_XOR_BITS_LENGTH_64BIT = 6
    
    GORILLA_ENCODING_ENDING_INTEGER = int(-2**63)
    GORILLA_ENCODING_ENDING_LONG = -2**63
    GORILLA_ENCODING_ENDING_FLOAT = float('nan')
    GORILLA_ENCODING_ENDING_DOUBLE = float('nan')

    BYTE_SIZE_PER_CHAR = 4

    STRING_ENCODING = "UTF-8"
    CHARSET = Charset.forName(STRING_ENCODING)

    CONFIG_FILE_NAME = "iotdb-engine.properties"

    MAGIC_STRING = "TsFile"
    VERSION_NUMBER_V2 = "000002"
    VERSION_NUMBER_V1 = "000001"
    
    VERSION_NUMBER = 0x03

    MIN_BLOOM_FILTER_ERROR_RATE = 0.01
    MAX_BLOOM_FILTER_ERROR_RATE = 0.1
    
    ARRAY_CAPACITY_THRESHOLD = 1000

    def __init__(self):
        self.group_size_in_byte = 128 * 1024 * 1024
        self.page_size_in_byte = 64 * 1024
        self.max_number_of_points_in_page = 1024 * 1024
        self.max_degree_of_index_node = 256

    def get_group_size_in_byte(self):
        return self.group_size_in_byte
    
    def set_group_size_in_byte(self, group_size_in_byte):
        self.group_size_in_byte = group_size_in_byte

    def get_page_size_in_byte(self):
        return self.page_size_in_byte
    
    def set_page_size_in_byte(self, page_size_in_byte):
        self.page_size_in_byte = page_size_in_byte

    # ... and so on for all the other methods
```

Please note that Python does not have direct equivalent of Java's `Serializable` interface. Also, Python does not require explicit getters and setters like Java does.