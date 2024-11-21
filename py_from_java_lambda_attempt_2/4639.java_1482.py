Here is the equivalent Python code:

```
class CoffSymbolType:
    T_NULL = 0x0000
    T_VOID = 0x0001
    T_CHAR = 0x0002
    T_SHORT = 0x0003
    T_INT = 0x0004
    T_LONG = 0x0005
    T_FLOAT = 0x0006
    T_DOUBLE = 0x0007
    T_STRUCT = 0x0008
    T_UNION = 0x0009
    T_ENUM = 0x000a
    T_MOE = 0x000b
    T_UCHAR = 0x000c
    T_USHORT = 0x000d
    T_UINT = 0x000e
    T_ULONG = 0x000f
    T_LONG_DOUBLE = 0x0010

    DT_NON = 0x0000
    DT_PTR = 0x0001
    DT_FCN = 0x0002
    DT_ARY = 0x0003

    @staticmethod
    def get_base_type(symbol_type):
        return symbol_type & 0xf

    @staticmethod
    def get_derived_type(symbol_type):
        return symbol_type & 0xf0
```

Note that I've used the `@staticmethod` decorator to define static methods in Python, which is equivalent to the `public final static` declaration in Java.