Here is the translation of the given Java code into equivalent Python:

```Python
class AddressOfPcodeArithmetic:
    def __init__(self):
        pass

    @staticmethod
    def unary_op(op, size_out, size_in1, in1):
        return None

    @staticmethod
    def binary_op(op, size_out, size_in1, in1, size_in2, in2):
        return None

    @staticmethod
    def from_const(value: int, size) -> object:
        # TODO: Do we care about Constant space?
        return None  # or some other appropriate value

    @staticmethod
    def from_const(value: 'BigInteger', size) -> object:
        return None  # or some other appropriate value

    @staticmethod
    def is_true(cond):
        raise AssertionError("Cannot decide branches using 'address of'")

    @staticmethod
    def to_concrete(value):
        raise AssertionError("Should not attempt to concretize 'address of'")
```

Please note that Python does not have direct equivalent for Java's enum. In this translation, I used a class with static methods instead.