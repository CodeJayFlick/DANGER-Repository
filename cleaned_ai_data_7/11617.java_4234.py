class OpBehaviorFloatSqrt:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_ SQRT)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> float:
        format = FloatFormatFactory.get_float_format(size_in)
        return format.op_sqrt(in1)

    def evaluate_big_integer_unary(self, size_out: int, size_in: int, in1: 'BigInteger') -> 'BigInteger':
        format = FloatFormatFactory.get_float_format(size_in)
        return format.op_sqrt(in1)
