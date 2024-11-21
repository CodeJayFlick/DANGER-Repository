Here is the equivalent Python code:

```Python
class ReferenceToReferenceAddressPairTableRowMapper:
    def map(self, row_object: 'ghidra.program.model.symbol.Reference', program: 'ghidra.program.model.listing.Program') -> tuple:
        return (row_object.get_from_address(), row_object.get_to_address())

# Note that the type hints are not actual Python types, but rather a way to indicate what types of objects should be passed in.
```

This code defines a class `ReferenceToReferenceAddressPairTableRowMapper` with a method `map`. The `map` method takes two parameters: `row_object`, which is expected to be an instance of the `ghidra.program.model.symbol.Reference` class, and `program`, which is expected to be an instance of the `ghidra.program.model.listing.Program` class. The method returns a tuple containing the from address and to address of the row object.

Note that Python does not have direct support for generics like Java or C#, so we do not need to specify types in the same way as those languages.