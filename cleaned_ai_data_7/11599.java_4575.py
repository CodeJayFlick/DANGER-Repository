class OpBehaviorCopy:
    def __init__(self):
        super().__init__(PcodeOp.COPY)

    def evaluate_unary(self, sizeout: int, sizein: int, in1) -> long:
        return in1

    def evaluate_big_integer_unary(self, sizeout: int, sizein: int, in1: 'BigInteger') -> 'BigInteger':
        return in1
