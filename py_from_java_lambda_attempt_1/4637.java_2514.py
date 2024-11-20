Here is the translation of the given Java code into Python:

```Python
class CoffSymbolSpecial:
    DOT_FILE = ".file"
    DOT_TEXT = ".text"
    DOT_DATA = ".data"
    DOT_BSS = ".bss"
    DOT_BB = ".bb"
    DOT_EB = ".eb"
    DOT_BF = ".bf"
    DOT_EF = ".ef"
    DOT_TARGET = ".target"
    DOT_NFAKE = ".nfake"
    DOT_EOS = ".eos"
    DOT_ETEXT = "etext"
    DOT_EDATA = "edata"
    DOT_END = "end"

    @staticmethod
    def is_special(symbol):
        declared_fields = CoffMachineType.__dict__.keys()
        for field in declared_fields:
            if not isinstance(field, str) or not field.startswith("DOT_"):
                continue
            try:
                value = getattr(CoffSymbolSpecial, field)
                if value == symbol.name:
                    return True
            except AttributeError:
                pass
        return False

    @staticmethod
    def get_storage_class(special_symbol):
        if special_symbol.name == CoffSymbolSpecial.DOT_FILE:
            return 0x10000 | 1
        elif special_symbol.name in [CoffSymbolSpecial.DOT_BB, CoffSymbolSpecial.DOT_EB]:
            return 0x20000 | 2
        elif special_symbol.name in [CoffSymbolSpecial.DOT_BF, CoffSymbolSpecial.DOT_EF]:
            return 0x40000 | 3
        elif special_symbol.name == CoffSymbolSpecial.DOT_EOS:
            return 0x80000000
        elif special_symbol.name in [CoffSymbolSpecial.DOT_TEXT, CoffSymbolSpecial.DOT_DATA, CoffSymbolSpecial.DOT_BSS]:
            return 0x10000 | 4
        else:
            return -1

class CoffMachineType:
    pass
```

Please note that this translation is not perfect and may require some adjustments to work correctly in your specific use case.