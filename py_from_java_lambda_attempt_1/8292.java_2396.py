Here is the translation of the Java code to Python:
```
class Reserved2MsSymbol:
    PDB_ID = 0x101d

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader'):
        super().__init__(pdb, reader)

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder: str) -> None:
        builder += self.get_symbol_type_name()

    def get_symbol_type_name(self) -> str:
        return "RESERVED2"
```
Note that I used the following Python features to translate the Java code:

* Classes and inheritance are represented using the `class` keyword.
* Methods are defined inside classes, with indentation indicating their scope.
* The `__init__` method is equivalent to a constructor in Java.
* The `super()` function is used to call the parent class's constructor or method.
* The `get_pdb_id`, `emit`, and `get_symbol_type_name` methods are translated from Java methods, with similar functionality.
* Python does not have an exact equivalent of Java's `@Override` annotation; instead, I simply defined the methods as they appear in the original code.

I hope this helps! Let me know if you have any questions.