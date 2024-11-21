Here is the translation of the given Java code into equivalent Python:

```Python
class OpBehaviorFloatMult:
    def __init__(self):
        super().__init__()

    def evaluate_binary(self, size_out: int, size_in: int, in1: float, in2: float) -> float:
        format = FloatFormat(size_in)
        return format.op_mult(in1, in2)

class FloatFormat:
    @staticmethod
    def get_float_format(size: int):
        # Assuming you have a function to create the desired float format here.
        pass

    def op_mult(self, in1: float, in2: float) -> float:
        # Assuming this is where your actual floating point multiplication logic goes.
        return in1 * in2
```

Note that Python does not support direct equivalent of Java's `BigInteger` class. It has its own way to handle large integers using the built-in integer type (`int`) or the `decimal` module for decimal arithmetic.

Also, note that this is a simplified translation and you may need to add more functionality depending on your specific requirements.