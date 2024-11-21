Here is the translation of the given Java code into equivalent Python:

```Python
class PrecompiledType16MsType:
    PDB_ID = 0x0013

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16, "StringSt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractPrecompiledTypeMsType:
    pass
```

Note that Python does not have direct equivalent of Java's abstract classes or interfaces. In this translation, I've used a regular class `AbstractPrecompiledTypeMsType` without any methods to mimic the concept of an abstract class in Java.

Also note that Python 3.5 and later versions support type hints for function parameters and return types using the `->` syntax. This is why you see `-> None` at the end of the `__init__` method, indicating that this method returns no value (i.e., it's a void method).