Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from decimal import Decimal, getcontext

class OpBehaviorFloatCeilTest(unittest.TestCase):

    def testEvaluateBinaryLong(self):
        op = OpBehaviorFloatCeil()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = ff.getEncoding(2.5)
        result = ff.opCeil(a)
        self.assertAlmostEqual(3.0, float(result), 10)

        a = ff.getEncoding(-2.5)
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(-2.0, float(result), 10)

        a = ff.getEncoding(float('inf'))
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(a, result)

        a = ff.getEncoding(-float('inf'))
        result = op.evaluateUnary(8, 8, a)
        self.assertEqual(a, result)

        a = ff.getEncoding(float('nan'))
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(a, float(result), 10)


    def testEvaluateBinaryBigInteger(self):
        op = OpBehaviorFloatCeil()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = ff.getBigFloatEncoding(2.5).to_python()
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(float(result), float(a))

        a = ff.getBigFloatEncoding(-2.5).to_python()
        result = op.evaluateUnary(8, 8, a)
        self.assertAlmostEqual(float(result), float(a))

        a = Decimal('inf')
        result = op.evaluateUnary(8, 8, a.to_python())
        self.assertEqual(a, result)

        a = -Decimal('inf')
        result = op.evaluateUnary(8, 8, a.to_python())
        self.assertEqual(a, result)

        a = Decimal('nan')
        result = op.evaluateUnary(8, 8, a.to_python())
        self.assertAlmostEqual(float(result), float(a))

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `BigInteger` class. Instead we use the decimal module which provides support for fast correctly rounded decimal floating point arithmetic.