Here is the equivalent Python code:

```Python
class DWARFEncoding:
    DW_ATE_VOID = 0x0
    DW_ATE_ADDRESS = 0x1
    DW_ATE_BOOLEAN = 0x2
    DW_ATE_COMPLEX_FLOAT = 0x3
    DW_ATE_FLOAT = 0x4
    DW_ATE_SIGNED = 0x5
    DW_ATE_SIGNED_CHAR = 0x6
    DW_ATE_UNSIGNED = 0x7
    DW_ATE_UNSIGNED_CHAR = 0x8
    DW_ATE_IMAGINARY_FLOAT = 0x9
    DW_ATE_PACKED_DECIMAL = 0xa
    DW_ATE_NUMERIC_STRING = 0xb
    DW_ATE_EDITED = 0xc
    DW_ATE_SIGNED_FIXED = 0xd
    DW_ATE_UNSIGNED_FIXED = 0xe
    DW_ATE_DECIMAL_FLOAT = 0xf
    DW_ATE_UTF = 0x10
    DW_ATE_LO_USER = 0x80
    DW_ATE_HI_USER = 0xff

    @staticmethod
    def get_type_name(encoding):
        return str(DWARFEncoding.__dict__.get('DW_ATE_' + hex(encoding)[2:], 'unknown_type_encoding'))
```

Please note that Python does not have direct equivalent of Java's `public` and `final` keywords. Also, in Python, we don't need to specify the type of a variable when declaring it.