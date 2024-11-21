Here is the translation of the given Java code into equivalent Python:

```Python
class OmfGroupRecord:
    def __init__(self):
        self.group_name_index = None
        self.group_name = None
        self.vma = -1  # Assigned (by linker) starting address of the whole group
        self.group = []

    def read_record_header(self, reader):
        pass

    def get_group_name(self):
        return self.group_name

    def set_start_address(self, val):
        self.vma = val

    def get_start_address(self):
        return self.vma

    def get_frame_datum(self):
        # TODO: Need to fill in a real segment selector
        return 0

    def num_segments(self):
        return len(self.group)

    def get_segment_component_type(self, i):
        if i < len(self.group):
            return self.group[i].component_type
        else:
            raise IndexError("Index out of range")

    def get_segment_index(self, i):
        if i < len(self.group):
            return self.group[i].segment_index
        else:
            raise IndexError("Index out of range")

    def get_address(self, language):
        addr_space = language.get_default_space()
        return addr_space.get_address(self.vma)

    def resolve_names(self, name_list):
        if not 0 < self.group_name_index <= len(name_list):
            raise OmfException("Group name index out of bounds")
        self.group_name = name_list[self.group_name_index - 1]

class GroupSubrecord:
    def __init__(self):
        self.component_type = None
        self.segment_index = None

    @classmethod
    def read(cls, reader):
        subrec = cls()
        subrec.component_type = reader.read_next_byte()
        subrec.segment_index = OmfRecord.read_index(reader)
        return subrec


class OmfException(Exception):
    pass
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation in Python, as the structure and syntax are different between the two languages.