Here is the translation of the given Java code into equivalent Python:

```Python
class CoffSymbolAuxFactory:
    @staticmethod
    def read(reader: 'BinaryReader', symbol) -> 'CoffSymbolAux':
        if symbol.get_derived_type(1) == 0 and symbol.get_basic_type() == 0:
            if symbol.get_storage_class() == 1:
                return CoffSymbolAuxFilename(reader)
            elif symbol.get_storage_class() == 2:
                return CoffSymbolAuxSection(reader)
            elif symbol.get_storage_class() in [3, 4, 5]:
                return CoffSymbolAuxTagName(reader)
            elif symbol.get_storage_class() == 6:
                return CoffSymbolAuxEndOfStruct(reader)
            elif symbol.get_storage_class() == 7:
                return CoffSymbolAuxBeginningOfBlock(reader)
            elif symbol.get_storage_class() == 8:
                return CoffSymbolAuxFunction(reader)

        if symbol.get_derived_type(1) == 2:
            if symbol.get_storage_class() == 9:
                return CoffSymbolAuxFunction(reader)
            elif symbol.get_storage_class() == 2:
                return CoffSymbolAuxFunction(reader)

        if symbol.get_derived_type(1) == 3:
            storage_classes = [10, 11, 12, 13, 14]
            if symbol.get_storage_class() in storage_classes:
                return CoffSymbolAuxArray(reader)
        
        return CoffSymbolAuxDefault(reader)


class BinaryReader:
    pass


class CoffSymbolType:
    DT_NON = 0
    T_NULL = 0

    DT_FC = 2
    DT_ARY = 3

    C_FILE = 1
    C_STAT = 2
    C_STRTAG = 3
    C_UNTAG = 4
    C_ENTAG = 5
    C_EOS = 6
    C_BLOCK = 7
    C_FCN = 8
    C_EXT = 9
    C_AUTO = 10
    C_STAT = 11
    C_MOS = 12
    C_MOU = 13
    C_TPDEF = 14


class CoffSymbolAux:
    pass


class CoffSymbolAuxFilename(CoffSymbolAux):
    def __init__(self, reader: 'BinaryReader'):
        pass


class CoffSymbolAuxSection(CoffSymbolAux):
    def __init__(self, reader: 'BinaryReader'):
        pass


class CoffSymbolAuxTagName(CoffSymbolAux):
    def __init__(self, reader: 'BinaryReader'):
        pass


class CoffSymbolAuxEndOfStruct(CoffSymbolAux):
    def __init__(self, reader: 'BinaryReader'):
        pass


class CoffSymbolAuxBeginningOfBlock(CoffSymbolAux):
    def __init__(self, reader: 'BinaryReader'):
        pass


class CoffSymbolAuxFunction(CoffSymbolAux):
    def __init__(self, reader: 'BinaryReader'):
        pass


class CoffSymbolAuxArray(CoffSymbolAux):
    def __init__(self, reader: 'BinaryReader'):
        pass


class CoffSymbolAuxDefault(CoffSymbolAux):
    def __init__(self, reader: 'BinaryReader'):
        pass
```

Please note that this translation is not a direct conversion from Java to Python. The code has been rewritten in a way that it can be easily understood and maintained by a Python developer.