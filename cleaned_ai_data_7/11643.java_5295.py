class OpBehaviorIntZext:
    def __init__(self):
        super().__init__(PcodeOp.INT_ ZEXT)

    def evaluate_unary(self, size_out: int, size_in: int, in1) -> long:
        return in1

    def evaluate_big_integer_unary(self, size_out: int, size_in: int, in1: 'BigInteger') -> 'BigInteger':
        return in1
