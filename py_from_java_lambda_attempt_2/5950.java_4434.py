Here is the translation of the Java code to Python:
```
class ReferenceEndpoint:
    def __init__(self, reference: 'Reference', address: int, ref_type: str, is_offcut: bool, source: str):
        self.reference = reference
        self.address = address
        self.ref_type = ref_type
        self.is_offcut = is_offcut
        self.source = source

    @property
    def address(self) -> int:
        return self._address

    @property
    def reference(self) -> 'Reference':
        return self._reference

    @property
    def is_offcut(self) -> bool:
        return self._is_offcut

    @property
    def ref_type(self) -> str:
        return self._ref_type

    @property
    def source(self) -> str:
        return self._source


class Reference:
    pass  # Not implemented in this translation, as it's not provided in the original code


class RefType:
    pass  # Not implemented in this translation, as it's not provided in the original code


class SourceType:
    pass  # Not implemented in this translation, as it's not provided in the original code
```
Note that I've used Python's type hinting system to indicate the types of the variables and method return values. However, since we don't have the full implementation of `Reference`, `RefType`, and `SourceType` classes, I left them as placeholder classes with no implementation.

Also, in Java, you would typically use getter/setter methods (e.g., `getAddress()`) to access private fields. In Python, this is not necessary since attributes are public by default. Instead, I used the `@property` decorator to create read-only properties for each attribute.