Here is the translation of the given Java code into equivalent Python:

```Python
class OpBehaviorFloatFloat2Float:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_FLOAT2FLOAT)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> float:
        format_out = FloatFormatFactory.get_float_format(size_out)
        format_in = FloatFormatFactory.get_float_format(size_in)
        return format_in.op_float_to_float(in1, format_out)

class FloatFormatFactory:
    @staticmethod
    def get_float_format(size):
        # This method should be implemented based on the actual requirements.
        pass

class PcodeOp:
    FLOAT_FLOAT2FLOAT = 0
```

Note that Python does not have direct equivalent of Java's `BigInteger` class. The equivalent in Python would be using a library like `gmpy2`. Also, I've assumed that there are separate classes for FloatFormat and FloatFormatFactory as per the given code structure.

The above translation is based on my understanding of the provided Java code. However, please note that actual implementation might vary depending upon specific requirements and constraints.