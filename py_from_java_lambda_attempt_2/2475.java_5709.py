Here is the translation of the Java code to Python:
```
class DBTraceOffsetReference:
    def __init__(self, ent):
        super().__init__(ent)

    @property
    def offset(self):
        return ent.ext

    @property
    def base_address(self):
        return Address(ent.to_address) - ent.ext
```
Note that I've used the `@property` decorator to create read-only properties for the `offset` and `base_address` attributes, similar to how Java has getter methods. In Python, we don't need explicit getters or setters like in Java.

Also, I've assumed that the `Address` class is a custom class defined elsewhere in your code, since it's not part of the standard library. If you want me to help with translating any other parts of the code, feel free to ask!