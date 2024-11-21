class OpBehaviorIntLess:
    def __init__(self):
        super().__init__()

    def evaluate_binary(self, sizeout, sizein, in1, in2):
        if sizein <= 0:
            return 0
        else:
            mask = (1 << sizein) - 1
            in1 &= mask
            in2 &= mask
            if in1 == in2:
                return 0
            elif sizein < 8:
                return int(in1 < in2)
            else:
                bit_mask = 0x80
                for _ in range(sizein - 1):
                    bit_mask <<= 8
                bit1 = (in1 & bit_mask) >> ((sizein - 1) * 8)
                bit2 = (in2 & bit_mask) >> ((sizein - 1) * 8)
                if bit1 != bit2:
                    return int(bit1 != 0)
                else:
                    return int(in1 < in2)

    def evaluate_binary_big_int(self, sizeout, sizein, in1, in2):
        return BigInteger(int((in1.compareTo(in2) < 0))) if in1.compareTo(in2) < 0 else BigInteger(0)
