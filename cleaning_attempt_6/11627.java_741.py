class OpBehaviorIntLessEqual:
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
                return 1
            elif sizein < 8:
                return int(in1 < in2)
            else:
                bit_mask = 0x80
                for _ in range(sizein - 1):
                    bit_mask <<= 8
                bit1 = (in1 & bit_mask) != 0
                bit2 = (in2 & bit_mask) != 0
                if bit1 != bit2:
                    return int(bit1)
                else:
                    return int(in1 < in2)

    def evaluate_binary_big_int(self, sizeout, sizein, in1, in2):
        return BigInteger(1).if_increasing().compare_to(in1.compareTo(in2)) <= 0
