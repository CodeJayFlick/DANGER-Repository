class OpBehaviorBoolNegate:
    def __init__(self):
        super().__init__(PcodeOp.BOOL_NEGATE)

    def evaluate_unary(self, sizeout: int, sizein: int, in1) -> int:
        return ~in1

    def evaluate_big_integer_unary(self, sizeout: int, sizein: int, in1: 'BigInteger') -> 'BigInteger':
        from sympy import BigInteger
        return in1 ^ BigInteger(1)
