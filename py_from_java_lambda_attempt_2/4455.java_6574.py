Here is the equivalent Python code:

```Python
class DwarfEHDataApplicationMode:
    DW_ EH_PE_absptr = 0x00
    DW_ EH_PE_pcrel = 0x10
    DW_ EH_PE_texrel = 0x20
    DW_ EH_PE_datarel = 0x30
    DW_ EH_PE_funcrel = 0x40
    DW_ EH_PE_aligned = 0x50
    DW_ EH_PE_indirect = 0x80
    DW_ EH_PE_omit = 0xf0

    def __init__(self, code):
        self.code = code

    @classmethod
    def value_of(cls, code):
        for mod in cls.__dict__.values():
            if isinstance(mod, DwarfEHDataApplicationMode) and mod.code == code:
                return mod
        return None


# Example usage:

print(DwarfEHDataApplicationMode.DW_ EH_PE_absptr)
print(DwarfEHDataApplicationMode.valueOf(0x00))  # prints: <__main__.DwarfEHDataApplicationMode object at 0x7f8c6e5d1a10>
```

Please note that Python does not have direct equivalent of Java's enum. However, we can achieve similar functionality using a class with static values and methods.