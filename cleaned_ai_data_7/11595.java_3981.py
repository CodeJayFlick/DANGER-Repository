class OpBehaviorBoolAnd:
    def __init__(self):
        super().__init__(PcodeOp.BOOL_AND)

    def evaluate_binary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        return in1 & in2

    def evaluate_big_integer(self, sizeout: int, sizein: int, in1: BigInteger, in2: BigInteger) -> BigInteger:
        from sympy import and_
        return and_(in1, in2)
