class OpBehaviorIntDiv:
    def __init__(self):
        super().__init__()

    def evaluate_binary(self, sizeout, sizein, in1, in2):
        if sizein <= 0 or in2 == 0:
            return 0
        if in1 == in2:
            return 1
        if sizein == 8:
            mask = (1 << 63)
            bit1 = in1 & mask  # Get the sign bits
            bit2 = in2 & mask
            if bit1 != 0 or bit2 != 0:  # use BigInteger to perform 64-bit unsigned division if one negative input
                big_in1 = Utils.bytes_to_big_int(Utils.long_to_bytes(in1, sizein), sizein)
                if big_in1.signum() < 0:
                    big_in1 = Utils.convert_to_unsigned_value(big_in1, sizein)
                big_in2 = Utils.bytes_to_big_int(Utils.long_to_bytes(in2, sizein), sizein)
                if big_in2.signum() < 0:
                    big_in2 = Utils.convert_to_unsigned_value(big_in2, sizein)
                result = big_in1.divide(big_in2)
                return result & Utils.calc_mask(sizeout)

        return (in1 // in2) & Utils.calc_mask(sizeout)

    def evaluate_binary_big_int(self, sizeout, sizein, in1, in2):
        if sizein <= 0 or in2.signum() == 0:
            return BigInteger.ZERO
        res = in1.divide(in2)
        return res

# Define the necessary utility functions (Utils) here.
