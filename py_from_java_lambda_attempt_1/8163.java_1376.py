Here is the translation of the given Java code into equivalent Python:

```Python
class FramePointerRelativeFullScopeDARMsSymbol:
    PDB_ID = 0x1144
    
    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.offset_to_frame_pointer = reader.parse_var_sized_offset(32)

    def get_pdb_id(self):
        return self.PDB_ID

    def get_symbol_type_name(self):
        return "DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE"

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: FrameOffset: {self.offset_to_frame_pointer:04X} FULL_SCOPE")
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the Javadoc comments. Also, in Python, we do not need to declare variable types like we do in Java.