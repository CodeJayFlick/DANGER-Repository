import unittest
from decimal import Decimal, getcontext

class OpBehaviorFloatTruncTest(unittest.TestCase):

    def testEvaluateBinaryLong(self):
        op = OpBehaviorFloatTrunc()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = ff.getEncoding(2.5)
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(result, 2)

        a = ff.getEncoding(-2.5)
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(result, -2)

        a = ff.getEncoding(float('inf'))
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(result, float('-inf'))

        a = ff.getEncoding(-float('inf'))
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(result, -float('inf'))

        # TODO: What should the correct result be?
        a = ff.getEncoding(float('nan'))
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(result, float('-0.0'))  # Note that NaN is not equal to itself in Python

    def testEvaluateBinaryBigInteger(self):
        op = OpBehaviorFloatTrunc()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = ff.getEncoding(ff.getBigFloat(2.5))
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(result, int(2))

        a = ff.getEncoding(ff.getBigFloat(-2.5))
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(result, -int(2))

        a = ff.getBigInfinityEncoding(False)
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(result, int(float('inf')))

        a = ff.getBigInfinityEncoding(True)
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(result, -int(float('-inf')))

        # TODO: What should the correct result be?
        a = ff.getBigNaNEncoding(False)
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(result, int(0))  # Note that NaN is not equal to itself in Python

if __name__ == '__main__':
    unittest.main()
