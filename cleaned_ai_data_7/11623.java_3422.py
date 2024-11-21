class OpBehaviorIntCarry:
    def __init__(self):
        super().__init__(PcodeOp.INT_CARRY)

    def evaluate_binary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        return 0 if Long.compareUnsigned(in1, (in1 + in2) & Utils.calc_mask(sizein)) <= 0 else 1

    def evaluate_big_int_binary(self, sizeout: int, sizein: int, in1: BigInteger, in2: BigInteger) -> BigInteger:
        if in1.signum() < 0 or in2.signum() < 0:
            raise AssertionError("Expected unsigned in values")
        
        res = (in1.compareTo(in1.add(in2).and(Utils.calc_big_mask(sizein))) > 0) and BigInteger.ONE or BigInteger.ZERO
        return res

import java.math.BigInteger as BigInt
from ghidra.pcode.utils import Utils
from ghidra.program.model.pcode import PcodeOp
