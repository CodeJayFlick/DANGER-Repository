Here is the translation of the given Java code into Python:

```Python
class AbstractLongOffsetPcodeExecutorStatePiece:
    def __init__(self, language: 'Language', arithmetic: 'PcodeArithmetic'):
        self.language = language
        self.arithmetic = arithmetic
        self.unique_space = self.language.get_address_factory().get_unique_space()

    def set_unique(self, offset: int, size: int, val):
        s = self.get_for_space(self.unique_space, True)
        self.set_in_space(s, offset, size, val)

    def get_unique(self, offset: int, size: int) -> 'T':
        s = self.get_for_space(self.unique_space, False)
        return self.get_from_space(s, offset, size)

    def get_for_space(self, space: 'AddressSpace', to_write: bool):
        # This method should be implemented in the subclass
        pass

    def set_in_space(self, space: 'S', offset: int, size: int, val):
        # This method should be implemented in the subclass
        pass

    def get_from_space(self, space: 'S', offset: int, size: int) -> 'T':
        # This method should be implemented in the subclass
        pass

    def get_from_null_space(self, size: int) -> 'T':
        return self.arithmetic.from_const(0, size)

    def offset_to_long(self, offset):
        # This method should be implemented in the subclass
        pass

    def set_var(self, space: 'AddressSpace', offset: object, size: int, truncate_addressable_unit: bool, val):
        if isinstance(space, ConstantSpace):
            raise ValueError("Cannot write to constant space")
        elif isinstance(space, UniqueSpace):
            self.set_unique(offset_to_long(offset), size, val)
        else:
            s = self.get_for_space(space, True)
            offset = truncate_offset(space, offset)
            self.set_in_space(s, offset, size, val)

    def get_var(self, space: 'AddressSpace', offset: object, size: int, truncate_addressable_unit: bool) -> 'T':
        if isinstance(space, ConstantSpace):
            return self.arithmetic.from_const(offset_to_long(offset), size)
        elif isinstance(space, UniqueSpace):
            return self.get_unique(offset_to_long(offset), size)
        else:
            s = self.get_for_space(space, False)
            if s is None:
                return self.get_from_null_space(size)
            offset = truncate_offset(space, offset)
            return self.get_from_space(s, offset, size)

class ConstantSpace:
    def __init__(self):
        pass

    @property
    def is_constant_space(self) -> bool:
        return True


class UniqueSpace:
    def __init__(self):
        pass

    @property
    def is_unique_space(self) -> bool:
        return True
```

Note that this translation assumes the following:

- The `Language`, `PcodeArithmetic`, and other classes are defined elsewhere in your code.
- The methods `get_address_factory()`, `from_const()`, and others should be implemented according to their original Java counterparts.

This Python version does not include all of the Java's type annotations, as they do not have direct equivalents in Python.