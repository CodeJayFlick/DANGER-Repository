Here is the equivalent Python code:

```Python
class DwarfEHDataDecodeFormat:
    def __init__(self, code):
        self.code = code

    @property
    def code(self):
        return self._code

    @classmethod
    def value_of(cls, code):
        for mod in cls.__dict__.values():
            if isinstance(mod, DwarfEHDataDecodeFormat) and mod.code == code:
                return mod
        return None


# Define the enum values as class attributes
DW_ EH_PE_absptr = DwarfEHDataDecodeFormat(0x00)
DW_ EH_PE_uleb128 = DwarfEHDataDecodeFormat(0x01)
DW_ EH_PE_udata2 = DwarfEHDataDecodeFormat(0x02)
DW_ EH_PE_udata4 = DwarfEHDataDecodeFormat(0x03)
DW_ EH_PE_udata8 = DwarfEHDataDecodeFormat(0x04)

DW_ EH_PE_signed = DwarfEHDataDecodeFormat(0x08)
DW_ EH_PE_sleb128 = DwarfEHDataDecodeFormat(0x09)
DW_ EH_PE_sdata2 = DwarfEHDataDecodeFormat(0x0a)
DW_ EH_PE_sdata4 = DwarfEHDataDecodeFormat(0x0b)
DW_ EH_PE_sdata8 = DwarfEHDataDecodeFormat(0x0c)

DW_ EH_PE_omit = DwarfEHDataDecodeFormat(0x0f)
```

Note that Python does not have built-in support for enums like Java or C++. Instead, we define a class `DwarfEHDataDecodeFormat` with an initializer and properties. The enum values are defined as class attributes.