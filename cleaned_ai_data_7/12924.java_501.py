import unittest
from ghidra.pcode.floatformat import FloatFormatFactory, FloatFormat
from ghidra.pcode.opbehavior import OpBehaviorFloatSub

class TestOpBehaviorFloatSub(unittest.TestCase):

    def test_evaluate_binary_long(self):
        op = OpBehaviorFloatSub()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = ff.getEncoding(1.5)
        b = ff.getEncoding(1.25)
        result = op.evaluateBinary(8, 8, a, b) # 1.5 - 1.25
        self.assertAlmostEqual(ff.getHostFloat(result), 0.25, places=10)

        a = ff.getEncoding(-1.25)
        result = op.evaluateBinary(8, 8, a, b) # -1.25 - 1.25
        self.assertAlmostEqual(ff.getHostFloat(result), -2.5, places=10)

        a = ff.getEncoding(float('inf'))
        result = op.evaluateBinary(8, 8, a, b) # +INFINITY - 1.25
        self.assertAlmostEqual(ff.getHostFloat(result), float('inf'), places=10)

        a = ff.getEncoding(-float('inf'))
        result = op.evaluateBinary(8, 8, a, b) # -INFINITY - 1.25
        self.assertAlmostEqual(ff.getHostFloat(result), -float('inf'), places=10)

        b = ff.getEncoding(-float('inf'))
        result = op.evaluateBinary(8, 8, a, b) # -INFINITY - -INFINITY
        self.assertAlmostEqual(ff.getHostFloat(result), float('nan'), places=10)

        b = ff.getEncoding(float('inf'))
        result = op.evaluateBinary(8, 8, a, b) # -INFINITY - +INFINITY
        self.assertAlmostEqual(ff.getHostFloat(result), -float('inf'), places=10)

        a = ff.getEncoding(float('nan'))
        b = ff.getEncoding(1.25)
        result = op.evaluateBinary(8, 8, a, b) # NaN - 1.25
        self.assertAlmostEqual(ff.getHostFloat(result), float('nan'), places=10)


    def test_evaluate_binary_biginteger(self):
        op = OpBehaviorFloatSub()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = ff.getEncoding(float(1.5))
        b = ff.getEncoding(float(1.25))
        result = op.evaluateBinary(8, 8, a, b) # 1.5 - 1.25
        self.assertAlmostEqual(ff.getHostFloat(result), float(0.25))

        a = ff.getEncoding(-float(1.25))
        result = op.evaluateBinary(8, 8, a, b) # -1.25 - 1.25
        self.assertAlmostEqual(ff.getHostFloat(result), -float(2.5))

        a = ff.getBigInfinityEncoding(False)
        result = op.evaluateBinary(8, 8, a, b) # +INFINITY - 1.25
        self.assertAlmostEqual(ff.getHostFloat(result), float('inf'))

        a = ff.getBigInfinityEncoding(True)
        result = op.evaluateBinary(8, 8, a, b) # -INFINITY - 1.25
        self.assertAlmostEqual(ff.getHostFloat(result), -float('inf'))

        b = ff.getBigInfinityEncoding(True)
        result = op.evaluateBinary(8, 8, a, b) # -INFINITY - -INFINITY
        self.assertAlmostEqual(ff.getHostFloat(result), float('nan'))

        b = ff.getBigInfinityEncoding(False)
        result = op.evaluateBinary(8, 8, a, b) # -INFINITY - +INFINITY
        self.assertAlmostEqual(ff.getHostFloat(result), -float('inf'))

        a = ff.getBigNaNEncoding(False)
        b = ff.getEncoding(float(1.25))
        result = op.evaluateBinary(8, 8, a, b) # NaN - 1.25
        self.assertAlmostEqual(ff.getHostFloat(result), float('nan'))


if __name__ == '__main__':
    unittest.main()
