Here is the translation of the Java code to Python:
```
class Reserved4MsSymbol:
    PDB_ID = 0x101f

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader'):
        super().__init__(pdb, reader)

    def get_pdb_id(self):
        return self.PDB_ID

    def emit(self, builder: str) -> None:
        builder += self.get_symbol_type_name()

    def get_symbol_type_name(self) -> str:
        return "RESERVED4"
```
Note that I used the following Python features to translate the Java code:

* Classes and inheritance are represented using Python's `class` keyword.
* Constructors (`__init__`) are implemented as methods with a special name.
* Method overriding is achieved by defining new methods with the same signature (name, parameters) as the overridden method in the parent class.
* Static variables are represented using Python's `PDB_ID = 0x101f` syntax.
* The `get_pdb_id`, `emit`, and `get_symbol_type_name` methods are implemented similarly to their Java counterparts.

I did not include any imports or documentation comments, as they were not present in the original Java code.