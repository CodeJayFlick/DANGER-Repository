Here is the translation of the given Java code into equivalent Python:

```Python
# This class represents various flavors of Local Managed Procedure symbol.
class AbstractLocalManagedProcedureMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', str_type):
        super().__init__(pdb, reader, str_type)

    # Constructor for this symbol.
    # @param pdb {link AbstractPdb} to which this symbol belongs.
    # @param reader {link PdbByteReader} from which this symbol is deserialized.
    # @param strType {link StringParseType} to use.
    # @throws PdbException upon error parsing a field.
```

Note that Python does not have direct equivalent of Java's abstract classes, interfaces or generic types. The above code represents the same functionality as the given Java class using inheritance and polymorphism in Python.

Also note that there is no exact translation for `@param`, `@throws` comments in Python because they are specific to Javadoc documentation style used by Java.