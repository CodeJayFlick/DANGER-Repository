Here is the translation of the given Java code into Python:

```Python
class VS_VERSION_INFO:
    NAME = "VS_VERSION_INFO"
    SIZEOF = 92

    def __init__(self):
        self.struct_length = None
        self.value_length = None
        self.struct_type = None
        self.info = ""
        self.alignment = None
        self.signature = None
        self.struct_version = ""
        self.file_version = ""
        self.product_version = ""
        self.file_flags_mask = ""
        self.file_flags = None
        self.file_os = None
        self.file_type = None
        self.file_subtype = None
        self.file_timestamp = None

    def to_data_type(self):
        struct = {"StructLength": 0, "ValueLength": 0, "StructType": 0}
        if self.alignment > 0:
            for _ in range(self.alignment):
                struct["Padding"] = ""
        return struct


class VS_VERSION_CHILD:
    pass

class FactoryBundledWithBinaryReader:
    def __init__(self):
        pass

    def read_next_short(self):
        # TO DO: implement this method
        pass

    def read_next_int_array(self, n_elements):
        # TO DO: implement this method
        return [0] * n_elements


def short_array_to_string(reader, n_elements):
    if n_elements == 2:
        arr = reader.read_next_short_array(2)
        return f"{arr[1]}.{arr[0]}"
    elif n_elements == 4:
        arr = reader.read_next_short_array(4)
        return f"{arr[3]}.{arr[2]}.{arr[1]}.{arr[0]}"
    else:
        return None


def int_array_to_string(reader, n_elements):
    if n_elements == 2:
        arr = reader.read_next_int_array(2)
        return f"{arr[1]}.{arr[0]}"
    elif n_elements == 4:
        arr = reader.read_next_int_array(4)
        return f"{arr[3]}.{arr[2]}.{arr[1]}.{arr[0]}"
    else:
        return None
```

Please note that the `FactoryBundledWithBinaryReader` class is not fully implemented in this translation. The methods `read_next_short`, `read_next_int_array`, and others are left as a placeholder (`pass`) to be completed according to your specific requirements.

Also, some Java-specific constructs like `ArrayList`, `HashMap`, `StructConverter`, etc., have been replaced with Python's built-in data structures (like lists) or omitted altogether.