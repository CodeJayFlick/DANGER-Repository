Here is the translation of the given Java code into equivalent Python:

```Python
class BoundImportDescriptor:
    NAME = "IMAGE_BOUND_IMPORT_DESCRIPTOR"
    IMAGE_SIZEOF_BOUND_IMPORT_DESCRIPTOR = 8

    def __init__(self):
        self.module_name = None
        self.time_date_stamp = None
        self.offset_module_name = None
        self.number_of_module_forwarder_refs = None
        self.forwarders = []

    @staticmethod
    def create_bound_import_descriptor(reader, reader_index, bidd_index) -> 'BoundImportDescriptor':
        bound_import_descriptor = BoundImportDescriptor()
        bound_import_descriptor.init_bound_import_descriptor(reader, reader_index, bidd_index)
        return bound_import_descriptor

    def init_bound_import_descriptor(self, reader, reader_index, bidd_index):
        self.time_date_stamp = reader.read_int(reader_index); reader_index += 4
        self.offset_module_name = reader.read_short(reader_index); reader_index += 2
        self.number_of_module_forwarder_refs = reader.read_short(reader_index); reader_index += 2

        if self.offset_module_name < 0:
            print("Invalid offsetModuleName", self.offset_module_name)
            return

        self.module_name = reader.read_ascii_string(bidd_index + self.offset_module_name)

        for i in range(self.number_of_module_forwarder_refs):
            forwarder_ref = BoundImportForwarderRef.create_bound_import_forwarder_ref(reader, reader_index, bidd_index)
            self.forwarders.append(forwarder_ref); reader_index += 8

    def __init__(self, name: str, time_date_stamp: int):
        self.module_name = name
        self.time_date_stamp = time_date_stamp

    @property
    def get_time_date_stamp(self) -> int:
        return self.time_date_stamp

    @property
    def get_offset_module_name(self) -> int:
        return self.offset_module_name

    @get_offset_module_name.setter
    def set_offset_module_name(self, offset: int):
        self.offset_module_name = offset

    @property
    def get_number_of_module_forwarder_refs(self) -> int:
        return self.number_of_module_forwarder_refs

    @property
    def get_module_name(self) -> str:
        return self.module_name

    def get_bound_import_forwarder_ref(self, index: int):
        if index >= len(self.forwarders):
            return None
        return self.forwarders[index]

    def __str__(self):
        buffer = "TimeStamp:" + hex(self.time_date_stamp) + ","
        buffer += "OffsetModuleName:" + str(Conv.short_to_int(self.offset_module_name)) + "[" + self.module_name + "]," + ","
        buffer += "NumberOfModuleForwarderRefs:" + str(Conv.short_to_int(self.number_of_module_forwarder_refs))
        for i in range(len(self.forwarders)):
            ref = self.forwarders[i]
            buffer += "\n\t" + "TimeStamp:" + hex(ref.get_time_date_stamp()) + ","
            buffer += "OffsetModuleName:" + str(Conv.short_to_int(ref.get_offset_module_name())) + "[" + ref.get_module_name() + "]," + ","
            buffer += "Reserved:" + str(Conv.short_to_int(ref.get_reserved()))
        return buffer

    def to_data_type(self):
        struct = StructureDataType(self.NAME + "_" + len(self.forwarders), 0)

        struct.add(DWORD, "TimeDateStamp", None)
        struct.add(WORD, "OffsetModuleName", None)
        struct.add(WORD, "NumberOfModuleForwarderRefs", None)

        for i in range(len(self.forwarders)):
            ref = self.forwarders[i]
            struct.add(ref.to_data_type())

        return struct

    def to_bytes(self):
        bytes = bytearray(BoundImportDescriptor.IMAGE_SIZEOF_BOUND_IMPORT_DESCRIPTOR + len(self.forwarders) * BoundImportForwarderRef.IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF)
        pos = 0
        dc.get_bytes(self.time_date_stamp, bytes, pos); pos += 4
        dc.get_bytes(self.offset_module_name, bytes, pos); pos += 2
        dc.get_bytes(self.number_of_module_forwarder_refs, bytes, pos); pos += 2

        for i in range(len(self.forwarders)):
            ref = self.forwarders[i]
            ref_bytes = ref.to_bytes()
            bytes[pos:pos + len(ref_bytes)] = ref_bytes; pos += len(ref_bytes)

        return bytes
```

Note that this Python code is equivalent to the given Java code, but it may not be exactly identical due to differences in syntax and semantics between the two languages.