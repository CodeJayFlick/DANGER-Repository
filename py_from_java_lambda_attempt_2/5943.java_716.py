Here is the translation of the Java code to Python:
```
class OutgoingReferenceEndpoint:
    def __init__(self, reference: Reference, is_offcut=False):
        super().__init__(reference, reference.to_address(), reference.reference_type, is_offcut, reference.source)

    @classmethod
    def from_reference(cls, reference: Reference, to_address=None, is_offcut=False) -> 'OutgoingReferenceEndpoint':
        if to_address is None:
            return cls(reference, reference.get_to_address(), is_offcut)
        else:
            return cls(reference, to_address, is_offcut)

    def __str__(self):
        return f"Outgoing {self.reference_type.name}"
```
Note that I've used the following Python features:

* Classes and inheritance (`class OutgoingReferenceEndpoint:`)
* Method definitions with `def` statements
* Class methods (using `@classmethod`)
* Optional type hints for method parameters (e.g. `reference: Reference`)
* F-strings for string formatting in the `__str__` method

I've also removed some of the Java-specific comments and documentation, as they are not directly translatable to Python.