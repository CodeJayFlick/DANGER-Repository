Here is the translation of the given Java code into Python:

```Python
class AbstractUnionMsType:
    """This class represents various flavors of C/CC++ Union type."""
    
    TYPE_STRING = "union"

    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader'):
        super().__init__(pdb, reader)

    def get_type_string(self):
        return self.TYPE_STRING
```

Note that Python does not have direct equivalent of Java's abstract classes and interfaces. However, we can achieve similar functionality using inheritance in Python.

In the above code:

- The `AbstractUnionMsType` class is defined as a regular class.
- It has an attribute `TYPE_STRING`.
- A constructor (`__init__`) method is defined which takes two parameters: `pdb` of type `'AbstractPdb'` and `reader` of type `'PdbByteReader'`. This is equivalent to the Java constructor.
- The `get_type_string` method returns the value of `self.TYPE_STRING`, similar to the overridden `getTypeString()` method in the original Java code.