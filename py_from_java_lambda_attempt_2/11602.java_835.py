Here is the translation of the given Java code into equivalent Python:

```Python
class OpBehaviorFloatAbs:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_ABS)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> float:
        format = FloatFormatFactory.get_float_format(size_in)
        return format.op_abs(in1)


class OpBehaviorFloatAbsBigInteger(OpBehaviorFloatAbs):
    @staticmethod
    def evaluate_unary(size_out: int, size_in: int, in1: 'BigInteger') -> 'BigInteger':
        format = FloatFormatFactory.get_float_format(size_in)
        return format.op_abs(in1)

```

Note that Python does not have a direct equivalent to Java's `long` and `BigInteger`. In this translation, I've used the built-in `float` type for the first method. For the second method, which takes a `BigInteger`, you would need to use an external library such as `gmpy2` or implement your own big integer class.

Also note that Python does not have direct equivalent of Java's static methods and classes. I've used instance methods instead.