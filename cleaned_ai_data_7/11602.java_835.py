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

