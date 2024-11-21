Here is the translation of the given Java interface into a Python class:

```Python
from enum import Enum
import ctypes as ct

class VTIndices(Enum):
    GET_SYMBOL_OPTIONS = 0
    ADD_SYMBOL_OPTIONS = 1
    REMOVE_SYMBOL_OPTIONS = 2
    SET_SYMBOL_OPTIONS = 3
    GET_NAME_BY_OFFSET = 4
    GET_OFFSET_BY_NAME = 5
    GET_NEAR_NAME_BY_OFFSET = 6
    GET_LINE_BY_OFFSET = 7
    GET_OFFSET_BY_LINE = 8
    GET_NUMBER_MODULES = 9
    GET_MODULE_BY_INDEX = 10
    GET_MODULE_BY_MODULE_NAME = 11
    GET_MODULE_BY_OFFSET = 12
    GET_MODULE_NAMES = 13
    GET_MODULE_PARAMETERS = 14
    GET_SYMBOL_MODULE = 15
    GET_TYPE_NAME = 16
    GET_TYPE_ID = 17
    GET_TYPE_SIZE = 18
    GET_FIELD_OFFSET = 19
    GET_SYMBOL_TYPE_ID = 20
    GET_OFFSET_TYPE_ID = 21
    READ_TYPED_DATA_VIRTUAL = 22
    WRITE_TYPED_DATA_VIRTUAL = 23
    OUTPUT_TYPED_DATA_VIRTUAL = 24
    READ_TYPED_DATA_PHYSICAL = 25
    WRITE_TYPED_DATA_PHYSICAL = 26
    OUTPUT_TYPED_DATA_PHYSICAL = 27
    GET_SCOPE = 28
    SET_SCOPE = 29
    RESET_SCOPE = 30
    GET_SCOPE_SYMBOL_GROUP = 31
    CREATE_SYMBOL_GROUP = 32
    START_SYMBOL_MATCH = 33
    GET_NEXT_SYMBOL_MATCH = 34
    END_SYMBOL_MATCH = 35
    RELOAD = 36
    GET_SYMBOL_PATH = 37
    SET_SYMBOL_PATH = 38
    APPEND_SYMBOL_PATH = 39
    GET_IMAGE_PATH = 40
    SET_IMAGE_PATH = 41
    APPEND_IMAGE_PATH = 42
    GET_SOURCE_PATH = 43
    GET_SOURCE_PATH_ELEMENT = 44
    SET_SOURCE_PATH = 45
    APPEND_SOURCE_PATH = 46
    FIND_SOURCE_FILE = 47
    GET_SOURCE_FILE_LINE_OFFSETS = 48

class IDebugSymbols:
    def __init__(self):
        self.vt_indices = VTIndices()

    @property
    def vt_index(self):
        return self.vt_indices.start + self.vt_indices.ordinal()

    def get_number_modules(self, loaded: ct.POINTER(ct.c_ulong), unloaded: ct.POINTER(ct.c_ulong)):
        pass  # implement this method

    def get_module_by_index(self, index: int, base: ct.POINTER(ct.c_ulonglong)):
        pass  # implement this method

    def get_module_by_name(self, name: str, start_index: int, index: ct.POINTER(ct.c_ulong), base: ct.POINTER(ct.c_ulonglong)):
        pass  # implement this method

    def get_module_by_offset(self, offset: ct.c_ulonglong, start_index: int, index: ct.POINTER(ct.c_ulong), base: ct.POINTER(ct.c_ulonglong)):
        pass  # implement this method

    def get_module_names(self, index: int, base: ct.c_ulonglong, image_name_buffer: bytearray, 
                         image_name_buffer_size: int, image_name_size: ct.POINTER(ct.c_ulong), module_name_buffer: bytearray,
                         module_name_buffer_size: int, module_name_size: ct.POINTER(ct.c_ulong)):
        pass  # implement this method

    def get_module_parameters(self, count: int, bases: ct.POINTER(ct.c_ulonglong), start: int, params: DEBUG_MODULE_PARAMETERS):
        pass  # implement this method

    def start_symbol_match(self, pattern: str, handle: ct.POINTER(ct.c_ulonglong)):
        pass  # implement this method

    def get_next_symbol_match(self, handle: ct.c_ulonglong, buffer: bytearray, buffer_size: int, match_size: ct.POINTER(ct.c_ulong), offset: ct.POINTER(ct.c_ulonglong)):
        pass  # implement this method

    def end_symbol_match(self, handle: ct.c_ulonglong):
        pass  # implement this method

    def get_symbol_path(self, a_buffer: bytearray, value: int, object: object):
        pass  # implement this method

    def set_symbol_path(self, path: str):
        pass  # implement this method

    def get_symbol_options(self):
        pass  # implement this method

    def set_symbol_options(self, options: int):
        pass  # implement this method
```

Please note that the Python code is not a direct translation of Java interface. The `ctypes` library was used to mimic some functionality from Java's `jna`.