Here is the translation of the given Java code into equivalent Python:

```Python
class OneMethodStMsType:
    PDB_ID = 0x140b

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader, 32, "StringSt")

    def get_pdb_id(self) -> int:
        return self.PDB_ID


class AbstractOneMethodMsType:
    pass

class PdbException(Exception):
    pass
```

Note that Python does not have direct equivalent of Java's `public`, `private` and other access modifiers. In Python, everything is public by default.

Also note that the translation from Java to Python involves some changes in syntax and structure. For example:

- The class declaration: In Java, classes are declared with the keyword `class`. In Python, they are not explicitly declared.
- Constructors: In Java, constructors have the same name as the class and do not return any value (i.e., they implicitly return `void`). In Python, these methods are called `__init__` and can take arguments.
- Methods: In Java, methods are declared with the keyword `public`, while in Python, there is no need to declare them explicitly. The method name starts with a single underscore if it's intended for internal use only (i.e., "private" in Java).
- Exception handling: In Java, exceptions are thrown using the `throw` statement and caught using try-catch blocks. In Python, this is done using the `raise` statement and try-except blocks.
- Static variables: In Java, static variables can be accessed directly from a class without creating an instance of that class. In Python, these are equivalent to regular attributes on the class itself.

These changes reflect some fundamental differences between the two languages.