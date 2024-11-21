Here is the translation of the given Java code into Python:

```Python
class ResourceType:
    def __init__(self):
        self.type = None
        self._type_bytes = None
        self.number_of_resources = 0
        self.offset_to_reference_list = 0
        self.reference_list = []
        self.resource_object = None

    def from_binary_reader(self, reader, header, map, resource_type_list_start_index):
        try:
            self.type = reader.read_int()
            self._type_bytes = reader.read_bytes(4)
            self.number_of_resources = reader.read_short()
            self.offset_to_reference_list = reader.read_short()

            self.parse_reference_list(reader, map)

            self.resource_object = ResourceTypeFactory.get_resource_object(reader, header, self)
        except Exception as e:
            print(f"Error: {e}")

    def parse_reference_list(self, reader, map):
        reference_list_start_index = map.map_start_index + map.resource_type_list_offset + self.offset_to_reference_list

        old_index = reader.pointer
        reader.set_pointer(reference_list_start_index)
        try:
            for i in range(self.number_of_resources + 1):
                self.reference_list.append(ReferenceListEntry(reader, map))
        finally:
            reader.set_pointer(old_index)

    def get_resource_object(self):
        return self.resource_object

    @property
    def type_(self):
        return self.type

    @type_.getter
    def type_(self):
        if isinstance(self._type_bytes, bytes) and all(0x20 <= b < 0x7F for b in self._type_bytes):
            return ''.join(map(chr, self._type_bytes))
        else:
            return f"0x{self.type:08X}"

    @property
    def number_of_resources_(self):
        return self.number_of_resources

    @number_of_resources_.getter
    def number_of_resources_(self):
        return self.number_of_resources - 1

    @property
    def offset_to_reference_list_(self):
        return self.offset_to_reference_list

    @offset_to_reference_list_.getter
    def offset_to_reference_list_(self):
        return self.offset_to_reference_list

    @property
    def reference_list_(self):
        return self.reference_list

    def to_data_type(self) -> 'DataType':
        name = f"{ResourceType.__name__}"
        struct = DataType(name, 0)
        if isinstance(self._type_bytes, bytes) and all(0x20 <= b < 0x7F for b in self._type_bytes):
            struct.add(StringDataType(), 4, "type", None)
        else:
            struct.add(DWORD, "type", None)
        struct.add(WORD, "numberOfResources", None)
        struct.add(WORD, "offsetToReferenceList", None)
        return struct

    def is_ascii(self) -> bool:
        for b in self._type_bytes:
            if not (0x20 <= b < 0x7F):
                return False
        return True


class ReferenceListEntry:
    pass


class ResourceTypeFactory:
    @staticmethod
    def get_resource_object(reader, header, resource_type):
        # TO DO: implement this method
        raise NotImplementedError("Method 'get_resource_object' is not implemented")
```

Please note that the `ReferenceListEntry` class and the `ResourceTypeFactory.get_resource_object()` method are placeholders in Python. You would need to replace them with actual implementations based on your specific requirements.