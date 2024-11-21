Here is the translation of the given Java code into Python:

```Python
class ModifierExMsType:
    PDB_ID = 0x1518
    
    class Modifier(enum.Enum):
        INVALID = enum.auto(), "INVALID"
        CONST = enum.auto(), "const"
        VOLATILE = enum.auto(), "volatile"
        UNALIGNED = enum.auto(), "unalignd"
        
        # HLSL modifiers
        HLSL_UNIFORM = enum.auto(), "__uniform__"
        HLSL_LINE = enum.auto(), "__line__"
        HLSL_TRIANGLE = enum.auto(), "__triangle__"
        HLSL_LINEADJ = enum.auto(), "__lineadj__"
        HLSL_TRIANGLEADJ = enum.auto(), "__triangleadj__"
        HLSL_LINEAR = enum.auto(), "__linear__"
        HLSL_CENTROID = enum.auto(), "__centroid__"
        HLSL_CONSTINTERP = enum.auto(), "__constinterp__"
        HLSL_NOPERSPECTIVE = enum.auto(), "__noperspective__"
        HLSL_SAMPLE = enum.auto(), "__sample__"
        HLSL_CENTER = enum.auto(), "__center__"
        HLSL_SNORM = enum.auto(), "__snorm__"
        HLSL_UNORM = enum.auto(), "__unorm__"
        HLSL_PRECISE = enum.auto(), "__precise__"
        HLSL_UAV_GLOBALLY_COHERENT = enum.auto(), "__uav_globally_coherent__"

    BY_VALUE = {modifier.value: modifier for modifier in Modifier}

    def __init__(self, pdb, reader):
        super().__init__()
        self.modified_record_number = RecordNumber.parse(pdb, reader, "TYPE", 32)
        count = reader.read_uint16()
        modifiers = []
        for _ in range(count):
            value = reader.read_uint16()
            modifier = Modifier.from_value(value)
            if modifier == Modifier.INVALID:
                # Should not happen, but could output a warning.
                pass
            else:
                modifiers.append(modifier)

    def emit(self, builder):
        builder.append(str(type(self).__name__))
        
    def __str__(self):
        return self.modified_record_number

    @classmethod
    def from_value(cls, val):
        return BY_VALUE.get(val, Modifier.INVALID)
```

Note that Python does not have an exact equivalent to Java's `enum` type. Instead, we use the built-in `enum` module in Python 3.4 and later versions or the `Enum` class from the `aenum` library for earlier versions of Python.

Also note that this translation is based on my understanding of your requirements. If you need any further modifications or have specific questions about certain parts, please let me know!