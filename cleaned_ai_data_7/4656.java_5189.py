class DebugInfoEntry:
    def __init__(self, compilation_unit: 'DWARFCompilationUnit', offset: int, abbreviation: 'DWARFAbbreviation'):
        self.compilation_unit = compilation_unit
        self.offset = offset
        self.abbreviation = abbreviation
        if abbreviation is not None:
            self.attributes = [None] * len(abbreviation.get_attributes())
        else:
            self.attributes = None

    def add_child(self, child: 'DebugInfoEntry'):
        if self.children is None:
            self.children = []
        self.children.append(child)

    @property
    def children(self):
        return self._children if self._children is not None else []

    def get_children(self) -> list:
        return self.children

    def get_children_by_tag(self, tag: int) -> list:
        result = []
        for child in self.get_children():
            if child.tag == tag:
                result.append(child)
        return result

    @property
    def has_children(self):
        return not self._children.empty()

    def set_parent(self, parent: 'DebugInfoEntry'):
        self.parent_offset = -1 if parent is None else parent.offset

    @property
    def parent(self) -> 'DebugInfoEntry':
        return DebugInfoEntry.get_entry_at_byte_offset(self.compilation_unit.program, self.parent_offset)

    @property
    def offset(self):
        return self._offset

    @property
    def tag(self):
        if self.abbreviation is None:
            return 0
        else:
            return self.abbreviation.tag

    def get_attributes(self) -> list:
        return self.attributes

    def has_attribute(self, attribute: int) -> bool:
        for aspec in self.abbreviation.get_attributes():
            if aspec.attribute == attribute:
                return True
        return False

    @property
    def abbreviation(self):
        return self._abbreviation

    def is_terminator(self) -> bool:
        return self.abbreviation is None or self.offset < 0

    def __str__(self):
        buffer = f"{type(self).__name__} - Offset: {hex(self.offset)}\n"
        if self.is_terminator():
            return buffer
        buffer += f"AbbreviationCode: {hex(0) if self.abbreviation is None else hex(self.abbreviation.abbreviation_code)}\n"
        buffer += f"{DWARFUtil.toString(DWARFTag, self.tag)}\n"

        for i in range(len(self.attributes)):
            aspec = self.abbreviation.get_attributes()[i]
            buffer += f"\tAttribute: {aspec.attribute} - {self.attributes[i]} - {aspec.attribute_form}\n"
        if len(self.children) > 0:
            buffer += f"\tChild count: {len(self.children)}\n"

        return buffer

    def __eq__(self, other):
        if self is None and other is not None or self is not None and other is None:
            return False
        if type(self) != type(other):
            return False
        return self.offset == other.offset

    def __hash__(self):
        prime = 31
        result = 1
        result *= prime * (result ^ (self.offset >> 32))
        return result


class DWARFCompilationUnit:
    pass


def get_entry_at_byte_offset(program, offset: int) -> 'DebugInfoEntry':
    # implement this method to retrieve a DebugInfoEntry from the program at the given byte offset
    pass

DWARFTag = object()
DWARFAbbreviation = object()

class DWARFAttribute:
    def __init__(self):
        pass


def main():
    compilation_unit = None  # replace with your actual DWARFCompilationUnit instance
    abbreviation = None  # replace with your actual DWARFAbbreviation instance

    entry = DebugInfoEntry(compilation_unit, offset=0x12345678, abbreviation=abbreviation)
    print(entry)


if __name__ == "__main__":
    main()
