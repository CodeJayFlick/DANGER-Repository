Here is the translation of the given Java code into equivalent Python:

```Python
class OpBehaviorFloatTrunc:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_TRUNC)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> float | int:
        if isinstance(in1, (int, float)):
            return FloatFormatFactory().get_float_format(size_in).op_trunc(in1, size_out)
        else:
            raise ValueError("Invalid input type")

    def evaluate_unary_big_int(self, size_out: int, size_in: int, in1) -> int | float:
        if isinstance(in1, (int)):
            return FloatFormatFactory().get_float_format(size_in).op_trunc(int(in1), size_out)
        else:
            raise ValueError("Invalid input type")
```

Please note that Python does not have direct equivalent of Java's BigInteger and PcodeOp. Also, the code assumes that in1 is either an integer or a float. If it can be something else (like None or string), you should add appropriate error handling.

Also, this translation might require some additional setup for FloatFormatFactory() as Python does not have direct equivalent of Java's factory pattern.