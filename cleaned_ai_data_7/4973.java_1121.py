class BoundImportForwarderRef:
    NAME = "IMAGE_BOUND_FORWARDER_REF"
    IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF = 8

    def __init__(self):
        self.time_date_stamp = None
        self.offset_module_name = None
        self.reserved = None
        self.module_name = None

    @classmethod
    def create_bound_import_forwarder_ref(cls, reader, reader_index, bidd_index):
        bound_import_forwarder_ref = cls()
        bound_import_forwarder_ref.init_bound_import_forwarder_ref(reader, reader_index, bidd_index)
        return bound_import_forwarder_ref

    def init_bound_import_forwarder_ref(self, reader, reader_index, bidd_index):
        self.time_date_stamp = reader.read_int(reader_index); reader_index += 4
        self.offset_module_name = reader.read_short(reader_index); reader_index += 2
        self.reserved = reader.read_short(reader_index); reader_index += 2

        if self.offset_module_name < 0:
            print("Invalid offsetModuleName", hex(self.offset_module_name))
            return

        self.module_name = reader.read_ascii_string(bidd_index + self.offset_module_name)

    def to_bytes(self, dc):
        bytes = bytearray(IMAGE_SIZEOF_BOUND_IMPORT_FORWARDER_REF)
        pos = 0
        dc.get_bytes(self.time_date_stamp, bytes, pos); pos += 4
        dc.get_bytes(self.offset_module_name, bytes, pos); pos += 2
        dc.get_bytes(self.reserved, bytes, pos); pos += 2
        return bytes

    @property
    def time_date_stamp(self):
        return self.time_date_stamp

    @time_date_stamp.setter
    def time_date_stamp(self, value):
        self.time_date_stamp = value

    @property
    def offset_module_name(self):
        return self.offset_module_name

    @offset_module_name.setter
    def offset_module_name(self, value):
        self.offset_module_name = value

    @property
    def reserved(self):
        return self.reserved

    @reserved.setter
    def reserved(self, value):
        self.reserved = value

    @property
    def module_name(self):
        return self.module_name

    @module_name.setter
    def module_name(self, value):
        self.module_name = value

    def to_data_type(self):
        struct = StructureDataType(NAME, 0)

        struct.add(DWORD, "TimeDateStamp", None)
        struct.add(WORD, "OffsetModuleName", None)
        struct.add(WORD, "Reserved", None)

        struct.set_category_path("/PE")

        return struct
