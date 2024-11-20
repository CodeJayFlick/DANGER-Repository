import unittest
from ghidra_pcode_opbehavior import OpBehaviorIntSlessEqual, Utils


class TestOpBehaviorIntSLess(unittest.TestCase):

    def testEvaluateBinaryLong(self):
        op = OpBehaviorIntSlessEqual()

        self.assertEqual(1, op.evaluate_binary(1, 4, 0, 0))
        self.assertEqual(0, op.evaluate_binary(1, 4, 1, 0))
        self.assertEqual(1, op.evaluate_binary(1, 4, 0, 1))
        self.assertEqual(1, op.evaluate_binary(1, 4, 2**31 - 1, 0))
        self.assertEqual(0, op.evaluate_binary(1, 4, 0, 2**31 - 1))
        self.assertEqual(1, op.evaluate_binary(1, 4, 2**31 - 1, 1))
        self.assertEqual(0, op.evaluate_binary(1, 4, 1, 2**31 - 1))
        self.assertEqual(1, op.evaluate_binary(1, 4, 2**31 - 1, 2**31 - 1))
        self.assertEqual(1, op.evaluate_binary(1, 8, 0, 0))
        self.assertEqual(0, op.evaluate_binary(1, 8, 1, 0))
        self.assertEqual(1, op.evaluate_binary(1, 8, 0, 1))
        self.assertEqual(1, op.evaluate_binary(1, 8, 2**63 - 1, 0))
        self.assertEqual(0, op.evaluate_binary(1, 8, 0, 2**63 - 1))
        self.assertEqual(1, op.evaluate_binary(1, 8, 2**63 - 1, 1))
        self.assertEqual(0, op.evaluate_binary(1, 8, 1, 2**63 - 1))
        self.assertEqual(1, op.evaluate_binary(1, 8, 2**63 - 1, 2**63 - 1))

    def testEvaluateBinaryBigInteger(self):
        op = OpBehaviorIntSlessEqual()
        NEGATIVE_ONE = Utils.convert_to_unsigned_value(-1)
        BIG_POSITIVE = 7 * (2 ** 63) + 0xFFFFFFFFFFFFFFFF
        BIG_NEGATIVE = 8 * (2 ** 63) - 0

        self.assertEqual(BigInteger(1), op.evaluate_binary(1, 16, BigInteger(0), BigInteger(0)))
        self.assertEqual(BigInteger(0), op.evaluate_binary(1, 16, BigInteger(1), BigInteger(0)))
        self.assertEqual(BigInteger(1), op.evaluate_binary(1, 16, BigInteger(0), BigInteger(1)))
        self.assertEqual(BigInteger(1), op.evaluate_binary(1, 16, NEGATIVE_ONE, BigInteger(0)))
        self.assertEqual(BigInteger(0), op.evaluate_binary(1, 16, BigInteger(0), BIG_NEGATIVE))
        self.assertEqual(BigInteger(1), op.evaluate_binary(1, 16, BIG_NEGATIVE, BigInteger(1)))
        self.assertEqual(BigInteger(0), op.evaluate_binary(1, 16, BigInteger(1), BIG_NEGATIVE))
        self.assertEqual(BigInteger(1), op.evaluate_binary(1, 16, BIG_NEGATIVE, BIG_NEGATIVE))
        self.assertEqual(BigInteger(1), op.evaluate_binary(1, 16, BIG_NEGATIVE, BIG_POSITIVE))


if __name__ == '__main__':
    unittest.main()
