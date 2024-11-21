Here is the translation of the given Java code into equivalent Python:

```Python
class OpBehaviorFloatDiv:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_DIV)

    def evaluate_binary(self, size_out: int, size_in: int, in1: float, in2: float) -> float:
        format = FloatFormatFactory.get_float_format(size_in)
        return format.op_div(in1, in2)


class OpBehaviorFloatDivBigInteger(OpBehaviorFloatDiv):
    @Override
    def evaluate_binary(self, size_out: int, size_in: int, in1: BigInteger, in2: BigInteger) -> BigInteger:
        format = FloatFormatFactory.get_float_format(size_in)
        return format.op_div(in1, in2)


# Usage example:

op_behavior = OpBehaviorFloatDiv()
size_out = 4
size_in = 8
in1 = float(10.5)
in2 = float(3.0)

result = op_behavior.evaluate_binary(size_out, size_in, in1, in2)
print(result)