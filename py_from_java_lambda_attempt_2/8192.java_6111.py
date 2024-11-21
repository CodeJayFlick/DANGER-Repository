Here is the translation of the given Java code into equivalent Python:

```Python
class HighLevelShaderLanguageRegDimDARMsSymbol:
    PDB_ID = 0x1150

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)

    @property
    def pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "DEFRANGE_HLSL"


class AbstractRegisterDimensionalityDARMsSymbol:
    pass


class PdbByteReader:
    pass


class AbstractPdb:
    pass
```

Please note that this is a direct translation of the Java code into Python. The `AbstractPdb`, `PdbByteReader` and `HighLevelShaderLanguageRegDimDARMsSymbol` classes are not defined in the original Java code, so I left them as abstract classes in the Python version.