Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractChangeExecutionModelMsSymbol:
    def __init__(self):
        pass

    class Model(enum.Enum):
        TABLE = ("DATA", 0x00)
        JUMPTABLE = ("JUMPTABLE", 0x01)
        DATAPAD = ("DATAPAD", 0x02)
        NATIVE = ("NATIVE", 0x20)
        COBOL = ("COBOL", 0x21)
        CODEPAD = ("CODEPAD", 0x22)
        CODE = ("CODE", 0x23)
        SQL = ("SQL", 0x30)
        PCODE = ("PCODE", 0x40)
        PCODE32MACINTOSH = ("PCODE for the Mac", 0x41)
        PCODE32MACINTOSH_NATIVE_ENTRY_POINT = ("PCODE for the Mac (Native Entry Point)", 0x42)
        JAVAINT = ("JAVAINT", 0x50)
        UNKNOWN = ("UNKNOWN MODEL", 0Xff)

    BY_VALUE = {val.value: val for val in Model}

    def __str__(self):
        return self.label

    @classmethod
    def from_value(cls, value):
        return BY_VALUE.get(value, cls.UNKNOWN)


class AbstractChangeExecutionModelMsSymbol:
    def __init__(self, pdb, reader, offset_size):
        super().__init__()
        self.offset = reader.parse_var_sized_offset(offset_size)
        self.segment = pdb.parse_segment(reader)
        self.model_val = reader.parse_unsigned_short_val()
        self.model = Model.from_value(self.model_val)


    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}:")
        builder.append(f"   segment, offset ={self.segment}:{self.offset}, model  ")
        builder.append(str(self.model))
        if self.model == AbstractChangeExecutionModelMsSymbol.Model.COBOL:
            builder.append("\n")
            switch = {
                0x00: f"   don't stop until next execution model\n",
                0x01: f"   inter-segment perform - treat as single call instruction\n",
                0x02: f"   false call - step into even with F10\n",
                0x03: f"   call to EXTCALL - step into {self.flag} call levels\n"
            }
            builder.append(switch.get(self.subtype, f"   UNKNOWN COBOL CONTROL 0x{self.subtype:x}\n"))
        elif self.model == AbstractChangeExecutionModelMsSymbol.Model.PCODE:
            builder.append("\n")
            builder.append(f"offsetToPcodeFunctionTable = {self.offset_to_pcode_function_table}, offsetToSegmentPcodeInformation = {self.offset_to_segment_pcode_information}")
        elif self.model in [AbstractChangeExecutionModelMsSymbol.Model.PCODE32MACINTOSH, AbstractChangeExecutionModelMsSymbol.Model.PCODE32MACINTOSH_NATIVE_ENTRY_POINT]:
            builder.append(f"callTable = {self.offset_to_function_table}, segment = {self.segment_of_function_table}\n")
        else:
            builder.append(f"={self.model_val:x}\n")

```

Note that Python does not have direct equivalent of Java's `enum` type. The above code uses the built-in `Enum` class from the `enum` module to create an enumeration in Python.