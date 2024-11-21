class OpBehaviorIntRight:
    def __init__(self):
        super().__init__(PcodeOp.INT_RIGHT)

    def evaluate_binary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        if in2 < 0 or in2 >= (8 * sizein):
            return 0
        return (in1 >> in2) & ((1 << sizeout) - 1)

    def evaluate_binary_bigint(self, sizeout: int, sizein: int, in1: BigInteger, in2: BigInteger) -> BigInteger:
        if in1.signum() < 0 or in2.signum() < 0:
            raise AssertionError("Expected unsigned in values")
        max_shift = BigInteger(sizein * 8)
        if in2 >= max_shift:
            return BigInteger(0)
        return in1.shift_right(in2.intValue())
