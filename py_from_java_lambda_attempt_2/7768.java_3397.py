Here is the translation of the given Java code into Python:

```Python
class EHCatchHandlerTypeModifier:
    NO_MODIFIERS = 0

    CONST_BIT = 1 << 0
    VOLATILE_BIT = 1 << 1
    UNALIGNED_BIT = 1 << 2
    REFERENCE_BIT = 1 << 3
    RESUMABLE_BIT = 1 << 4
    ALL_CATCH_BIT = 1 << 6
    COMPLUS_BIT = 0x80000000

    def __init__(self, modifiers):
        self.modifiers = modifiers

    def is_bit_set(self, bit_to_check):
        return (self.modifiers & bit_to_check) == bit_to_check

    @property
    def is_const(self):
        return self.is_bit_set(EHCatchHandlerTypeModifier.CONST_BIT)

    @property
    def is_volatile(self):
        return self.is_bit_set(EHCatchHandlerTypeModifier.VOLATILE_BIT)

    @property
    def is_unaligned(self):
        return self.is_bit_set(EHCatchHandlerTypeModifier.UNALIGNED_BIT)

    @property
    def is_by_reference(self):
        return self.is_bit_set(EHCatchHandlerTypeModifier.REFERENCE_BIT)

    @property
    def is_resumable(self):
        return self.is_bit_set(EHCatchHandlerTypeModifier.RESUMABLE_BIT)

    @property
    def is_all_catch(self):
        return self.is_bit_set(EHCatchHandlerTypeModifier.ALL_CATCH_BIT)

    @property
    def is_complus(self):
        return self.is_bit_set(EHCatchHandlerTypeModifier.COMPLUS_BIT)

    def __hash__(self):
        return hash(self.modifiers)

    def __eq__(self, other):
        if self == other:
            return True
        if not isinstance(other, EHCatchHandlerTypeModifier):
            return False
        return self.modifiers == other.modifiers
```

Note that Python does not have a direct equivalent to Java's `package` declaration. Also, the class is defined using the standard Python syntax for defining classes (`class`). The properties are implemented as getter methods in Python (using the `@property` decorator).