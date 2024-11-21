Here is the translation of the given Java code into Python:

```Python
class AbstractGlobalThreadStorageMsSymbol:
    """This class represents various flavors of Global Thread Storage symbol.
    
    Note: we do not necessarily understand each of these symbol type classes.  Refer to 
          the base class for more information."""
    
    def __init__(self, pdb, reader, internals):
        """Constructor for this symbol.
        
        Args:
            pdb (AbstractPdb): The PDB object that this symbol belongs to
            reader (PdbByteReader): The byte reader from which this symbol is deserialized
            internals (ThreadStorageSymbolInternals): The internal structure used by this symbol
        
        Raises:
            PdbException: Upon error parsing a field"""
        
        super().__init__(pdb, reader, internals)
```

Note that Python does not have direct equivalents for Java's abstract classes and methods. However, we can achieve similar functionality using inheritance and polymorphism in Python. The `super()` function is used to call the constructor of the parent class (in this case, `AbstractThreadStorageMsSymbol`).