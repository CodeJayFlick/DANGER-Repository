class OpBehaviorBoolXor:
    def __init__(self):
        super().__init__(PcodeOp.BOOL_XOR)

    def evaluate_binary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        return in1 ^ in2

    def evaluate_big_integer(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        from gmpy2 import mpz
        res = mpz(in1).xor(mpz(in2))
        return int(res)
