Here is the translation of the Java code into Python:

```Python
class CliStreamBlob:
    def __init__(self, header, offset, rva, reader):
        self.header = header
        self.offset = offset
        self.rva = rva
        self.reader = reader
        self.blob_map = {}

    @property
    def name(self):
        return "#Blob"

    def parse(self) -> bool:
        self.reader.seek(self.offset)
        first_byte = self.reader.read(1)[0]
        if first_byte != 0x00:
            raise ValueError("Invalid stream header")
        
        bytes_read = 1
        while bytes_read < self.header.size():
            blob_size = int.from_bytes(self.reader.read(blob_size), 'little')
            blob_data = self.reader.read(blob_size)
            blob_map[bytes_read] = (blob_size, blob_data)
            bytes_read += blob_size

        return True

    def get_blob(self, index: int) -> tuple:
        if index not in self.blob_map:
            raise ValueError("Invalid index")
        return self.blob_map[index]

    def update_blob(self, updated_blob: dict, addr: Address, program: Program):
        # Get and validate the containing structure at the given address
        data = program.get_listing().get_defined_data_containing(addr)
        if not isinstance(data, Data) or not data.is_structure():
            raise ValueError("Containing data is not a structure")

        struct = data.get_data_type()
        
        # Make sure there is an old blob at the given address
        offset = addr.subtract(data.get_address())
        component = struct.get_component_at(offset)
        if component is None:
            raise ValueError("Existing blob was not found")
        
        # Make sure the old blob has the same size as the new blob
        old_blob_type = component.get_data_type()
        new_blob_type = updated_blob['data_type']
        if old_blob_type.length != new_blob_type.length:
            raise ValueError(f"Cannot replace existing blob with {updated_blob['name']} because they have different sizes")

        # Update the blob
        struct.replace_at_offset(offset, new_blob_type, updated_blob['size'], updated_blob['name'], updated_blob['comment'])

    def to_data_type(self) -> DataType:
        struct = StructureDataType(CategoryPath(PATH), self.header.name)
        for index, (blob_size, _) in self.blob_map.items():
            blob_name = f"[{index:02X}]"
            struct.add(blob_size, "Reserved", always_zero=True)

        return struct
```

Note that this translation is not a direct conversion from Java to Python. Some changes were made to the code structure and variable types to make it more idiomatic in Python.