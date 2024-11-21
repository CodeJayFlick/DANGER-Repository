Here is the translation of the given Java code into equivalent Python:

```Python
class OpBehaviorFloatSqrt:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_ SQRT)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> float:
        format = FloatFormatFactory.get_float_format(size_in)
        return format.op_sqrt(in1)

    def evaluate_big_integer_unary(self, size_out: int, size_in: int, in1: 'BigInteger') -> 'BigInteger':
        format = FloatFormatFactory.get_float_format(size_in)
        return format.op_sqrt(in1)
```

Note that Python does not have a direct equivalent to Java's `long` or `BigInteger`. In this translation, I assumed the input and output values are floating point numbers. If you need support for arbitrary-precision arithmetic (like BigInteger in Java), you would typically use libraries like `gmpy2` or `decimal`.