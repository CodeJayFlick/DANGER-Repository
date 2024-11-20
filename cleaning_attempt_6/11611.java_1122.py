class OpBehaviorFloatLessEqual:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_LESSEQUAL)

    def evaluate_binary(self, size_out: int, size_in: int, in1: float, in2: float) -> bool:
        format = FloatFormat(size_in)
        return format.op_less_equal(in1, in2)


class FloatFormat:
    @staticmethod
    def get_float_format(size: int):
        # Assuming the implementation of this method is similar to Java's FloatFormatFactory.getFloatFormat()
        pass

    def op_less_equal(self, a: float, b: float) -> bool:
        # Implementation for floating point comparison (less equal)
        return a <= b


class PcodeOp:
    FLOAT_LESSEQUAL = "FLOAT_LESSEQUAL"
