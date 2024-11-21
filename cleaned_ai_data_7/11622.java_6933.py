class OpBehaviorIntAnd:
    def __init__(self):
        super().__init__()

    def evaluate_binary(self, sizeout, sizein, in1, in2):
        return in1 & in2

    def evaluate_big_integer(self, sizeout, sizein, in1, in2):
        from gmpy2 import mpz
        return mpz(in1).and_(mpz(in2))
