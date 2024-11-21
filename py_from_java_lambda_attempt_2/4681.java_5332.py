Here is the translation of the Java code into equivalent Python:

```Python
import enum

class DWARFOpcode(enum.IntEnum):
    DW_OP_addr = 0x3
    DW_OP_deref = 0x6
    DW_OP_const1u = 0x8
    DW_OP_const1s = 0x9
    # ... (all the other opcodes)

class DWARFOperandType(enum.Enum):
    ADDR = enum.auto()
    U_BYTE = enum.auto()
    S_Byte = enum.auto()
    U_SHORT = enum.auto()
    S_Short = enum.auto()
    U_INT = enum.auto()
    S_Int = enum.auto()
    U_LONG = enum.auto()
    S_Long = enum.auto()
    U_LEB128 = enum.auto()
    S_LEB128 = enum.auto()
    # ... (all the other operand types)

class DWARFExpressionOpCodes:
    UNSUPPORTED_OPCODES = [DWARFOpcode.DW_OP_deref_size, 
                            DWARFOpcode.DW_OP_xderef_size,
                            # ... (all the unsupported opcodes)
                           ]

    OP_TO_OPERAND_TYPES = {
        DWARFOpcode.DW_OP_addr: [DWARFOperandType.ADDR],
        DWARFOpcode.DW_OP_const1u: [DWARFOperandType.U_BYTE],
        # ... (all the opcode to operand type mappings)
       }

    @classmethod
    def get_operand_types_for(cls, opcode):
        return cls.OP_TO_OPERAND_TYPES.get(opcode, [])

    @classmethod
    def is_valid_opcode(cls, opcode):
        for field in vars(cls).values():
            if isinstance(field, enum.IntEnum) and field.name.startswith("DW_OP_") and field.value == opcode:
                return True
        return False

    @classmethod
    def to_string(cls, opcode):
        return str(opcode)
```

Note that Python does not have a direct equivalent of Java's `enum` type. Instead, we use the built-in `int` type for opcodes and create an enumeration class using the `enum` module from the standard library.