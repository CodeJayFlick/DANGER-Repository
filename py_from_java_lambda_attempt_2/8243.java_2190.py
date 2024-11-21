Here is the translation of the given Java code into equivalent Python:

```Python
class ManagedLocalOrParameterSIMR2StMsSymbol:
    PDB_ID = 0x1027

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 16, "StringUtf8")

    def get_pdb_id(self) -> int:
        return self.PDB_ID

    def get_symbol_type_name(self) -> str:
        return "MANMANYREG2_ST"
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. The concept is similar but implemented differently in Python.

In this translation, I've used the same class name as in the original code for simplicity. However, it would be more idiomatic to use a singular form (e.g., `ManagedLocalOrParameterSimR2StMsSymbol`) since classes are typically represented by nouns and should not end with "s" unless they represent multiple instances of that noun.

The constructor (`__init__` method) is similar in both languages, but Python's type hints are used to specify the types of parameters. The `super().__init__(...)` call is equivalent to calling the superclass's constructor.

The `get_pdb_id` and `get_symbol_type_name` methods are also similar, with only minor differences due to Python's syntax and lack of explicit return statements.