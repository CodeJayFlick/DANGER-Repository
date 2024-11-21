class OpBehaviorIntScarry:
    def __init__(self):
        pass

    def evaluate_binary(self, sizeout, sizein, in1, in2):
        res = in1 + in2

        a = (in1 >> ((sizein * 8) - 1)) & 1
        b = (in2 >> ((sizein * 8) - 1)) & 1
        r = (res >> ((sizein * 8) - 1)) & 1

        r ^= a
        a ^= b
        a ^= 1
        r &= a
        return r

    def evaluate_binary_big_int(self, sizeout, sizein, in1, in2):
        res = in1 + in2

        a = (in1.bit_length() > ((sizein * 8) - 1))
        b = (in2.bit_length() > ((sizein * 8) - 1))
        r = (res.bit_length() > ((sizein * 8) - 1))

        r ^= a
        a ^= b
        a ^= True
        r &= a
        return int(r)
