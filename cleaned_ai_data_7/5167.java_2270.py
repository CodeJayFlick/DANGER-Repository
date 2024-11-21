class SectionHeader:
    def __init__(self):
        self.name = None
        self.physical_address = 0
        self.virtual_size = 0
        self.virtual_address = 0
        self.size_of_raw_data = 0
        self.pointer_to_raw_data = 0
        self.pointer_to_relocations = 0
        self.pointer_to_linenumbers = 0
        self.number_of_relocations = 0
        self.number_of_linenumbers = 0
        self.characteristics = 0

    @staticmethod
    def read_section_header(reader, index, string_table_offset):
        result = SectionHeader()
        result.reader = reader
        if isinstance(string_table_offset, int) and string_table_offset != -1:
            try:
                name_offset = int(result.name[1:])
                result.name = reader.read_ascii_string(string_table_offset + name_offset)
            except ValueError:
                pass  # ignore error, section name will remain as it was

        reader.set_pointer_index(index + SectionHeader.IMAGE_SIZEOF_SHORT_NAME)

        result.physical_address = reader.read_next_int()
        result.virtual_size = reader.read_next_int()
        result.virtual_address = reader.read_next_int()
        result.size_of_raw_data = reader.read_next_int()
        result.pointer_to_raw_data = reader.read_next_int()
        result.pointer_to_relocations = reader.read_next_int()
        result.pointer_to_linenumbers = reader.read_next_int()
        result.number_of_relocations = reader.read_next_short()
        result.number_of_linenumbers = reader.read_next_short()
        result.characteristics = reader.read_next_int()

        return result

    def get_name(self):
        return self.name

    def get_readable_name(self):
        readable_name = ""
        for char in self.name:
            if 0x20 <= ord(char) <= 0x7e:  # is readable ascii?
                readable_name += char
            else:
                readable_name += '_'
        return readable_name

    @property
    def physical_address(self):
        return self.physical_address

    @physical_address.setter
    def physical_address(self, value):
        self.physical_address = value

    @property
    def virtual_size(self):
        return self.virtual_size

    @virtual_size.setter
    def virtual_size(self, value):
        self.virtual_size = value

    @property
    def size_of_raw_data(self):
        return self.size_of_raw_data

    @size_of_raw_data.setter
    def size_of_raw_data(self, value):
        self.size_of_raw_data = value

    @property
    def pointer_to_raw_data(self):
        return self.pointer_to_raw_data

    @pointer_to_raw_data.setter
    def pointer_to_raw_data(self, value):
        self.pointer_to_raw_data = value

    @property
    def pointer_to_relocations(self):
        return self.pointer_to_relocations

    @pointer_to_relocations.setter
    def pointer_to_relocations(self, value):
        self.pointer_to_relocations = value

    @property
    def pointer_to_linenumbers(self):
        return self.pointer_to_linenumbers

    @pointer_to_linenumbers.setter
    def pointer_to_linenumbers(self, value):
        self.pointer_to_linenumbers = value

    @property
    def number_of_relocations(self):
        return self.number_of_relocations

    @number_of_relocations.setter
    def number_of_relocations(self, value):
        self.number_of_relocations = value

    @property
    def number_of_linenumbers(self):
        return self.number_of_linenumbers

    @number_of_linenumbers.setter
    def number_of_linenumbers(self, value):
        self.number_of_linenumbers = value

    @property
    def characteristics(self):
        return self.characteristics

    @characteristics.setter
    def characteristics(self, value):
        self.characteristics = value

    def to_bytes(self, dc):
        padded_name = bytearray(SectionHeader.IMAGE_SIZEOF_SHORT_NAME)
        name_bytes = self.name.encode()
        if len(name_bytes) < SectionHeader.IMAGE_SIZEOF_SHORT_NAME:
            System.arraycopy(name_bytes, 0, padded_name, 0, len(name_bytes))
        else:
            for i in range(len(padded_name)):
                padded_name[i] = ord('_')

        return padded_name + dc.to_bytes(self.virtual_size) + \
               dc.to_bytes(self.virtual_address) + \
               dc.to_bytes(self.size_of_raw_data) + \
               dc.to_bytes(self.pointer_to_raw_data) + \
               dc.to_bytes(self.pointer_to_relocations) + \
               dc.to_bytes(self.pointer_to_linenumbers) + \
               dc.to_bytes(self.number_of_relocations) + \
               dc.to_bytes(self.number_of_linenumbers)

    def get_data_stream(self):
        return self.reader.get_byte_provider().get_input_stream(self.pointer_to_raw_data)

    @staticmethod
    def to_datatype():
        union = UnionDataType("Misc")
        union.add(DWORD, "PhysicalAddress", None)
        union.add(DWORD, "VirtualSize", None)
        union.set_category_path(CategoryPath("/PE"))

        struct = StructureDataType(SectionHeader.NAME, 0)
        struct.add(ArrayDataType(ASCII, 8, 1), "Name", None)
        struct.add(union, "Misc", None)
        struct.add(IBO32, "VirtualAddress", None)
        struct.add(DWORD, "SizeOfRawData", None)
        struct.add(DWORD, "PointerToRawData", None)
        struct.add(DWORD, "PointerToRelocations", None)
        struct.add(DWORD, "PointerToLinenumbers", None)
        struct.add(WORD, "NumberOfRelocations", None)
        struct.add(WORD, "NumberOfLinenumbers", None)

    def write_header(self, raf, dc):
        if self.size_of_raw_data == 0:
            return

        raf.seek(self.pointer_to_raw_data)

        #if (block.getType() == MemoryBlock.INITIALIZED) || (block.getType() == MemoryBlock.LIVE)):
        block_bytes = bytearray((int)(self.virtual_size))
        self.reader.get_byte_provider().get_input_stream(self.pointer_to_raw_data).read(block_bytes)
        raf.write(block_bytes)

    def update_pointers(self, offset):
        if self.pointer_to_raw_data > 0:
            self.pointer_to_raw_data += offset
        if self.pointer_to_relocations > 0:
            self.pointer_to_relocations += offset
        if self.pointer_to_linenumbers > 0:
            self.pointer_to_linenumbers += offset

    def set_virtual_size(self, size):
        self.virtual_size = size

    def set_size_of_raw_data(self, size):
        self.size_of_raw_data = size


class UnionDataType:
    def __init__(self, name):
        self.name = name
        self.members = []

    def add(self, dtype, name, default_value=None):
        member = {"dtype": dtype, "name": name}
        if default_value is not None:
            member["default"] = default_value

        self.members.append(member)

    def set_category_path(self, path):
        pass  # todo


class StructureDataType:
    def __init__(self, name, size):
        self.name = name
        self.size = size
        self.members = []

    def add(self, dtype, name, default_value=None):
        member = {"dtype": dtype, "name": name}
        if default_value is not None:
            member["default"] = default_value

        self.members.append(member)

    def set_category_path(self, path):
        pass  # todo


class CategoryPath:
    def __init__(self, path):
        self.path = path
