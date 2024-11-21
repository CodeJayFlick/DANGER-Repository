Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra.pcode.floatformat import FloatFormatFactory, FloatFormat
from ghidra.pcode.opbehavior import OpBehaviorFloatRound

class TestOpBehaviorFloatRound(unittest.TestCase):

    def test_evaluate_binary_long(self):
        op = OpBehaviorFloatRound()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = ff.getEncoding(2.5)
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), 3.0, places=10)

        a = ff.getEncoding(2.25)
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), 2.0, places=10)

        a = ff.getEncoding(2.75)
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), 3.0, places=10)

        a = ff.getEncoding(-2.5)
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), -2.0, places=10)

        a = ff.getEncoding(-2.25)
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), -2.0, places=10)

        a = ff.getEncoding(-2.75)
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual.ff.getHostFloat(result), -3.0, places=10)

        a = ff.getEncoding(float('inf'))
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), float('inf'), places=10)

        a = ff.getEncoding(-float('inf'))
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual.ff.getHostFloat(result), -float('inf'), places=10)

        a = ff.getEncoding(float('nan'))
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), float('nan'), places=10)


    def test_evaluate_binary_biginteger(self):
        op = OpBehaviorFloatRound()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = ff.getEncoding(float(2.5))
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), float(3.0))

        a = ff.getEncoding(float(2.25))
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual.ff.getHostFloat(result), float(2.0)

        a = ff.getEncoding(float(2.75))
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), float(3.0))

        a = ff.getEncoding(-float(2.5))
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual.ff.getHostFloat(result), -float(2.0)

        a = ff.getEncoding(-float(2.25))
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual.ff.getHostFloat(result), -float(2.0)

        a = ff.getEncoding(-float(2.75))
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual.ff.getHostFloat(result), -float(3.0)

        a = ff.getBigInfinityEncoding(False)
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), float('inf'))

        a = ff.getBigInfinityEncoding(True)
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual.ff.getHostFloat(result), -float('inf')

        a = ff.getBigNaNEncoding(False)
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(ff.getHostFloat(result), float('nan'))

if __name__ == '__main__':
    unittest.main()
```

This Python code uses the `unittest` module to define two test cases: one for evaluating binary operations with long values and another for evaluating binary operations with big integers. The tests are similar in structure, but they use different types of input (longs vs. big integers) and check that the results match expected floating-point values.