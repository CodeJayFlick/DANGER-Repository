Here is the translation of the Java code to Python:
```
# This class represents various flavors of C++ Class type.
class AbstractClassMsType(AbstractCompositeMsType):
    TYPE_STRING = "class"

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader'):
        super().__init__(pdb, reader)

    def get_type_string(self) -> str:
        return self.TYPE_STRING
```
Note that I've used Python's type hinting system to indicate the types of the `pdb` and `reader` parameters in the constructor. This is not strictly necessary for a working program, but it can be helpful for documentation and static analysis tools.

Also, I've kept the same naming conventions as the original Java code, with some minor adjustments to fit Python's syntax (e.g., using underscores instead of camelCase).