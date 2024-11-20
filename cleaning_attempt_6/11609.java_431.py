class OpBehaviorFloatInt2Float:
    def __init__(self):
        super().__init__(PcodeOp.FLOAT_INT2FLOAT)

    def evaluate_unary(self, size_out: int, size_in: int, in1: float) -> float:
        format = FloatFormat(size_out)
        return format.op_int2float(in1, size_in)

    def evaluate_unary_biginteger(self, size_out: int, size_in: int, in1: 'BigInteger') -> 'BigInteger':
        format = FloatFormat(size_out)
        return format.op_int2float(in1, size_in, True)


class BigInteger:
    pass


class PcodeOp:
    FLOAT_INT2FLOAT = None
