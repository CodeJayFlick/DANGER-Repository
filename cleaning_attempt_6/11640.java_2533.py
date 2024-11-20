class OpBehaviorIntSright:
    def __init__(self):
        super().__init__(PcodeOp.INT_SRIGHT)

    def evaluate_binary(self, sizeout, sizein, in1, in2):
        max_shift = (sizein * 8) - 1
        if in2 < 0 or in2 > max_shift:
            if Utils.signbit_negative(in1, sizein):
                return Utils.calc_mask(sizein)
            else:
                return 0

        res = None
        if Utils.signbit_negative(in1, sizein):
            res = in1 >> in2
            mask = Utils.calc_mask(sizein)
            mask = (mask >> in2) ^ mask
            res |= mask
        else:
            res = in1 >> in2
        return res

    def evaluate_binary_big_int(self, sizeout, sizein, in1, in2):
        if in1.signum() < 0 or in2.signum() < 0:
            raise AssertionError("Expected unsigned in values")

        signbit = (sizein * 8) - 1
        max_shift = BigInteger(signbit)
        if in2 > max_shift:
            in2 = max_shift

        if in1.test_bit(signbit):
            in1 = Utils.convert_to_signed_value(in1, sizein)

        return in1.shift_right(int(in2))
