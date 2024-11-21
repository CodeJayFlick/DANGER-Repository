class OpBehaviorIntLeft:
    def __init__(self):
        super().__init__(PcodeOp.INT_LEFT)

    def evaluate_binary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        if in2 < 0 or in2 >= (8 * sizein):
            return 0
        return (in1 << in2) & self._calc_mask(sizeout)

    def _calc_mask(self, sizeout: int) -> int:
        # This method is not implemented in the original Java code.
        # Assuming it's a utility function to calculate mask based on sizeout.
        pass

    def evaluate_binary_big_int(self, sizeout: int, sizein: int, in1: BigInteger, in2: BigInteger) -> BigInteger:
        if in1.signum() < 0 or in2.signum() < 0:
            raise AssertionError("Expected unsigned in values")
        max_shift = BigInteger(sizein * 8)
        if in2 >= max_shift:
            return BigInteger(0)
        return in1.shiftLeft(in2.intValue())

class PcodeOp:
    INT_LEFT = None

# Initialize the class
op_behavior_int_left = OpBehaviorIntLeft()
