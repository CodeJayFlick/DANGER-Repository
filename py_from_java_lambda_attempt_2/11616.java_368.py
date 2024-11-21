Here is the translation of the given Java code into Python:

```Python
class OpBehaviorFloatRound:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_ROUND)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> float | int:
        if isinstance(in1, (int)):
            return round(float(in1))
        elif isinstance(in1, float):
            return round(in1)
        else:
            raise ValueError("Invalid input type")

    def evaluate_unary_big_int(self, size_out: int, size_in: int, in1) -> int | float:
        if isinstance(in1, (int)):
            return round(float(in1))
        elif isinstance(in1, float):
            return round(in1)
        else:
            raise ValueError("Invalid input type")
```

Note that Python does not have a direct equivalent to Java's `BigInteger` class. In this translation, I've assumed that the operation on big integers should be done using floating point operations and then rounding the result. If you need more precise control over integer arithmetic, consider using the `decimal` module in Python.