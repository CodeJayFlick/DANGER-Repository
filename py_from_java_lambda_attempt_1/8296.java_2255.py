Here is the translation of the given Java code into Python:

```Python
class SeparatedCodeFromCompilerSupportMsSymbol:
    PDB_ID = 0x1132

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.parent_pointer = reader.parse_unsigned_int_val()
        self.end_pointer = reader.parse_unsigned_int_val()
        self.block_length = reader.parse_unsigned_int_val()
        flags = reader.parse_unsigned_int_val()
        self.process_flags(flags)

    def get_pdb_id(self):
        return PDB_ID

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: [{builder.format("%04X:%08X", self.section, self.offset)}, Length: %08X," % (self.block_length))
        builder.append(f"Parent: %08X, End: %08X\n" % (self.parent_pointer, self.end_pointer))
        builder.append(f"   Parent scope begins: [{builder.format("%04X:%08X", self.section_parent, self.offset_parent)}]\n")
        if self.is_lexical_scope:
            builder.append("   Separated code flags: lexscope ")
        else:
            builder.append("   Separated code flags: ")

        if self.returns_to_parent:
            builder.append("retparent")
        else:
            builder.append("")
        builder.append("\n")

    def get_symbol_type_name(self):
        return "SEPCODE"

    @property
    def parent_pointer(self):
        return self._parent_pointer

    @parent_pointer.setter
    def parent_pointer(self, value):
        self._parent_pointer = value

    @property
    def end_pointer(self):
        return self._end_pointer

    @end_pointer.setter
    def end_pointer(self, value):
        self._end_pointer = value

    @property
    def block_length(self):
        return self._block_length

    @block_length.setter
    def block_length(self, value):
        self._block_length = value

    @property
    def is_lexical_scope(self):
        return self._is_lexical_scope

    @is_lexical_scope.setter
    def is_lexical_scope(self, value):
        self._is_lexical_scope = value

    @property
    def returns_to_parent(self):
        return self._returns_to_parent

    @returns_to_parent.setter
    def returns_to_parent(self, value):
        self._returns_to_parent = value

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    @property
    def offset_parent(self):
        return self._offset_parent

    @offset_parent.setter
    def offset_parent(self, value):
        self._offset_parent = value

    @property
    def section(self):
        return self._section

    @section.setter
    def section(self, value):
        self._section = value

    @property
    def section_parent(self):
        return self._section_parent

    @section_parent.setter
    def section_parent(self, value):
        self._section_parent = value

    def process_flags(self, flags_in):
        self.is_lexical_scope = (flags_in & 0x0001) == 0x0001
        flags_in >>= 1
        self.returns_to_parent = (flags_in & 0x0001) == 0x0001
```

Please note that Python does not have direct equivalent of Java's `abstract` class or interface, so I did not translate those parts as they are specific to the language and would require significant changes in how you structure your code.