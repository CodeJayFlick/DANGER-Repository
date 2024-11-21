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
