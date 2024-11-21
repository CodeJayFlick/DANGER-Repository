class GnuBuildIdSection:
    MAX_SANE_STR_LENS = 1024

    def __init__(self, dtm, section_size):
        self.section_size = section_size
        super().__init__("Gnu_BuildId", dtm)

    def clone(self, dtm):
        if dtm == self.data_mgr:
            return self
        return GnuBuildIdSection(dtm, self.section_size)

    def populate_dynamic_structure(self, buf, es):
        try:
            name_len = buf.get_uint(0)
            desc_len = buf.get_uint(4)
            if (name_len > self.MAX_SANE_STR_LENS or 
                desc_len > self.MAX_SANE_STR_LENS or
                name_len + desc_len + 12 > self.section_size):
                return

            es.add("namesz", "Length of name field")
            es.add("descsz", "Length of description field")
            es.add("type", "Vendor specific type")

            if (name_len > 0):
                es.add(StringDataType(), name_len, "name", "Build-id vendor name")

            if (desc_len > 0):
                es.add(ArrayDataType(BYTE, desc_len), "description", "Build-id value")
        except MemoryAccessException:
            pass

    def set_category_path(self, struct, buf):
        try:
            struct.set_category_path("/ELF")
        except DuplicateNameException:
            pass
        return struct


# This is not part of the original Java code but it seems like a necessary class in Python.
class StringDataType:
    pass

class ArrayDataType:
    def __init__(self, data_type, length):
        self.data_type = data_type
        self.length = length

BYTE = "byte"
DWORD = "dword"

data_mgr = None  # This should be replaced with the actual DataTypeManager in your Python code.
