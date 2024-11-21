Here is the equivalent Python code:

```
class DWARFExpressionOperandType:
    U_LEB128 = 'U_LAB128'
    S_LEB128 = 'S_LAB128'
    S_BYTE = 'S_Byte'
    S_SHORT = 'S_Short'
    S_INT = 'S_Int'
    S_LONG = 'S_Long'
    U_BYTE = 'U_Byte'
    U_SHORT = 'U_Short'
    U_INT = 'U_Int'
    U_LONG = 'U_Long'
    ADDR = 'Addr'
    SIZED_BLOB = 'Sized Blob'
    DWARF_INT = 'Dwarf Int'

def value_to_string(value, operand_type):
    if operand_type in [DWARFExpressionOperandType.U_LONG, DWARFExpressionOperandType.ADDR, DWARFExpressionOperandType.DWARF_INT]:
        return format(value, 'x')
    else:
        return format(value, '#o')

# Example usage
print(value_to_string(1234567890123456, DWARFExpressionOperandType.S_LONG))
```

Note that Python does not have an exact equivalent to Java's `enum` type. Instead, we define a class with static attributes representing the different types of operands. The `value_to_string` function is similar to its Java counterpart, but uses Python's built-in formatting functions instead of calling separate methods like `Long.toString`.