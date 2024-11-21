Here is the translation of the given Java code into Python:

```Python
class OpBehaviorFloatFloor:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_FLOOR)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> float | int:
        if isinstance(in1, (int, float)):
            return self._evaluate_float(size_in, in1)
        elif isinstance(in1, int):
            return self._evaluate_int(size_in, in1)

    def _evaluate_float(self, size_in: int, in1: float) -> float:
        format = FloatFormatFactory.get_format(size_in)
        return format.op_floor(in1)

    def _evaluate_int(self, size_in: int, in1: int) -> int | float:
        if size_in == 4:
            # Assuming that the integer is a 32-bit signed integer
            return self._int_to_float(in1)
        elif size_in == 8:
            # Assuming that the integer is an 64-bit signed integer
            return self._long_to_float(in1)

    def _int_to_float(self, in1: int) -> float:
        return struct.unpack('f', struct.pack('i', in1))[0]

    def _long_to_float(self, in1: int) -> float:
        return struct.unpack('d', struct.pack('q', in1))[0]
```

Please note that the Python code does not exactly replicate the Java code. The main differences are:

- In Python, we do not need to explicitly specify types for variables or method parameters.
- We use `isinstance()` function to check if a variable is of certain type (like int or float).
- We define separate methods `_evaluate_float` and `_evaluate_int` to handle the evaluation of floating point numbers and integers respectively. This is because Python does not support operator overloading like Java, so we need to explicitly specify how to evaluate these operations.
- The `struct` module in Python is used to convert between integer types (like int or long) and float type.

This code assumes that you have the following functions defined elsewhere:

```Python
PcodeOp.FLOAT_FLOOR
FloatFormatFactory.get_format(size_in)
```

These are equivalent to their Java counterparts.