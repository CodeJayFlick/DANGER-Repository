Here is the equivalent Python code:

```Python
class BootImageHeaderV1:
    def __init__(self):
        self.recovery_dtbo_size = None
        self.recovery_dtbo_offset = None
        self.header_size = None

    def from_binary_reader(self, reader):
        self.recovery_dtbo_size = int.from_bytes(reader.read(4), 'little')
        self.recovery_dtbo_offset = int.from_bytes(reader.read(8), 'little')
        self.header_size = int.from_bytes(reader.read(4), 'little')

    @property
    def recovery_dtbo_size(self):
        return self.recovery_dtbo_size

    @property
    def recovery_dtbo_offset(self):
        return self.recovery_dtbo_offset

    @property
    def header_size(self):
        return self.header_size

    def to_data_type(self):
        structure = {}
        try:
            structure['name'] = 'boot_img_hdr_v1'
        except Exception as e:
            pass
        
        structure['recovery dtbo size'] = int.from_bytes(structure.get('recovery_dtbo_size', b'').ljust(4, b'\0'), 'little')
        structure['recovery dtbo offset'] = int.from_bytes(structure.get('recovery_dtbo_offset', b'').ljust(8, b'\0'), 'little')
        structure['header size'] = int.from_bytes(structure.get('header_size', b'').ljust(4, b'\0'), 'little')

        return structure
```

Please note that Python does not have direct equivalent of Java's `BinaryReader` and `DataType`. This code assumes you are reading binary data from a file or some other source. The `to_data_type` method is also simplified as there seems to be no clear way in Python to create a structured data type like Java's `Structure`.