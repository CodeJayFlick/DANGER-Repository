Here is the translation of the given Java code into Python:

```Python
class AbstractProcedureReferenceMsSymbol:
    """This class represents various flavors of Procedure Reference symbol.
    
    Note: we do not necessarily understand each of these symbol type classes. 
          Refer to the base class for more information."""
    
    def __init__(self, pdb, reader, internals):
        """Constructor for this symbol.
        
        @param pdb AbstractPdb to which this symbol belongs
        @param reader PdbByteReader from which this symbol is deserialized
        @param internals the internal structure to be used for this symbol
        """
        super().__init__(pdb, reader, internals)
```

Note that Python does not have direct equivalents of Java's `abstract` and `throws` keywords. The equivalent in Python would be using a base class with abstract methods (in case you want to make the subclass implement certain methods) or raising exceptions explicitly when needed.