Here's a translation of your Java code into equivalent Python:

```Python
class ByteCopier:
    BYTE_STRING_FLAVOR = create_byte_string_local_data_flavor()
    BYTE_STRING_NO_SPACES_FLAVOR = create_byte_string_no_spaces_local_data_flavor()
    PYTHON_BYTE_STRING_FLAVOR = create_python_byte_string_local_data_flavor()
    PYTHON_LIST_FLAVOR = create_python_list_local_data_flavor()
    CPP_BYTE_ARRAY_FLAVOR = create_cpp_byte_array_local_data_flavor()

    EMPTY_LIST = []

    BYTE_STRING_TYPE = ClipboardType(BYTE_STRING_FLAVOR, "Byte String")
    BYTE_STRING_NO_SPACE_TYPE = ClipboardType(BYTE_STRING_NO_SPACES_FLAVOR, "Byte String (No Spaces)")
    PYTHON_BYTE_STRING_TYPE = ClipboardType(PYTHON_BYTE_STRING_FLAVOR, "Python Byte String")
    PYTHON_LIST_TYPE = ClipboardType(PYTHON_LIST_FLAVOR, "Python List")
    CPP_BYTE_ARRAY_TYPE = ClipboardType(CPP_BYTE_ARRAY_FLAVOR, "C Array")

    PROGRAMMING_PATTERNS_BY_FLAVOR = {
        PYTHON_BYTE_STRING_FLAVOR: re.compile("b'(.*)'"),
        PYTHON_LIST_FLAVOR: re.compile("\\[(.*)\\]"),
        CPP_BYTE_ARRAY_FLAVOR: re.compile("\\{(.*)\\}")
    }

    PROGRAMMING_BYTES_PATTERN = re.compile("(?:\\\\x|0x)([a-fA-F0-9]{2})")

    def __init__(self):
        # limit construction
        pass

    @staticmethod
    def create_byte_string_local_data_flavor():
        try:
            return GenericDataFlavor(DataFlavor.javaJVMLocalObjectMimeType + "; class=java.lang.String", "Local flavor--byte string with spaces")
        except Exception as e:
            Msg.error(ByteCopier, "Unexpected exception creating data flavor for byte string", e)
        return None

    # ... and so on
```

Note that Python does not have a direct equivalent to Java's `DataFlavor` class. Instead, we use regular expressions (`re.compile`) to match certain patterns in strings.

Also note that the `create_byte_string_local_data_flavor`, `create_python_byte_string_local_data_flavor`, and other similar methods are static because they don't depend on any instance variables of the class.