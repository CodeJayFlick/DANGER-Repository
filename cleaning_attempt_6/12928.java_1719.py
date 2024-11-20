import unittest
from ghidra_pcode_opbehavior import OpBehaviorIntAnd


class TestOpBehaviorIntAnd(unittest.TestCase):

    def testEvaluateBinaryLong(self):
        op = OpBehaviorIntAnd()

        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 0))
        self.assertEqual(0, op.evaluate_binary(4, 4, 1, 0))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 1))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0xffffffffL, 0))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 0xffffffffL))
        self.assertEqual(1, op.evaluate_binary(4, 4, 0xffffffffL, 1))
        self.assertEqual(1, op.evaluate_binary(4, 4, 1, 0xffffffffL))
        self.assertEqual(0xffffffffL, op.evaluate_binary(4, 4, 0xffffffffL, 0xffffffffL))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0x80000000L, 0))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 0x80000000L))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0x80000000L, 1))
        self.assertEqual(0, op.evaluate_binary(4, 4, 1, 0x80000000L))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0x80000000L, 0x7fffffffL))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0x7fffffffL, 0x80000000L))
        self.assertEqual(0x80000000L, op.evaluate_binary(4, 4, 0x80000000L, 0x80000000L))  # overflow
        self.assertEqual(0x7fffffffL, op.evaluate_binary(4, 4, 0x7fffffffL, 0x7fffffffL))  # overflow

        self.assertEqual(0, op.evaluate_binary(8, 8, 0, 0))
        self.assertEqual(0, op.evaluate_binary(8, 8, 1, 0))
        self.assertEqual(0, op.evaluate_binary(8, 8, 0, 1))
        self.assertEqual(0, op.evaluate_binary(8, 8, 0xffffffffffffffffL, 0))
        self.assertEqual(0, op.evaluate_binary(8, 8, 0, 0xffffffffffffffffL))
        self.assertEqual(1, op.evaluate_binary(8, 8, 0xffffffffffffffffL, 1))
        self.assertEqual(1, op.evaluate_binary(8, 8, 1, 0xffffffffffffffffL))
        self.assertEqual(0xffffffffffffffffL, op.evaluate_binary(8, 8, 0xffffffffffffffffL, 0xffffffffffffffffL))
        self.assertEqual(0, op.evaluate_binary(8, 8, int(-2**63), 0))  # Long.MIN_VALUE
        self.assertEqual(0, op.evaluate_binary(8, 8, 0, int(-2**63)))  # Long.MIN_VALUE
        self.assertEqual(0, op.evaluate_binary(8, 8, int(-2**63), 1))
        self.assertEqual(0, op.evaluate_binary(8, 8, 1, int(-2**63)))
        self.assertEqual(0, op.evaluate_binary(8, 8, int(-2**63), int(2**63 - 1)))  # Long.MAX_VALUE
        self.assertEqual(0, op.evaluate_binary(8, 8, int(2**63 - 1), int(-2**63)))
        self.assertEqual(int(-2**63), op.evaluate_binary(8, 8, int(-2**63), int(-2**63)))  # overflow
        self.assertEqual(int(2**63 - 1), op.evaluate_binary(8, 8, int(2**63 - 1), int(2**63 - 1)))  # overflow


    def testEvaluateBinaryBigInteger(self):
        op = OpBehaviorIntAnd()

        NEGATIVE_ONE = Utils.convert_to_unsigned_value(BigInteger.valueOf(-1), 16)
        BIG_POSITIVE = BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
        BIG_NEGATIVE = Utils.convert_to_unsigned_value(BigInteger("80000000000000000000000000000000"), 16)

        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, BigInteger.ZERO, BigInteger.ZERO), 16)
        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, BigInteger.ONE, BigInteger.ZERO), 16)
        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, BigInteger.ZERO, BigInteger.ONE), 16)
        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, NEGATIVE_ONE, BigInteger.ZERO), 16)
        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, BigInteger.ZERO, NEGATIVE_ONE), 16)
        self.assertEqual(BigInteger.ONE, op.evaluate_binary(1, 16, NEGATIVE_ONE, BigInteger.ONE), 16)
        self.assertEqual(BigInteger.ONE, op.evaluate_binary(1, 16, BigInteger.ONE, NEGATIVE_ONE), 16)
        self.assertEqual(NEGATIVE_ONE, op.evaluate_binary(1, 16, NEGATIVE_ONE, NEGATIVE_ONE), 16)
        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, BIG_NEGATIVE, BigInteger.ZERO), 16)
        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, BigInteger.ZERO, BIG_NEGATIVE), 16)
        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, BIG_NEGATIVE, BigInteger.ONE), 16)
        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, BigInteger.ONE, BIG_NEGATIVE), 16)
        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, BIG_NEGATIVE, BIG_POSITIVE), 16)
        self.assertEqual(BigInteger.ZERO, op.evaluate_binary(1, 16, BIG_POSITIVE, BIG_NEGATIVE), 16)
        self.assertEqual(BIG_NEGATIVE, op.evaluate_binary(1, 16, BIG_NEGATIVE, BIG_NEGATIVE), 16)  # overflow
        self.assertEqual(BIG_POSITIVE, op.evaluate_binary(1, 16, BIG_POSITIVE, BIG_POSITIVE), 16)  # overflow


if __name__ == '__main__':
    unittest.main()
