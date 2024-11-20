import unittest
from decimal import Decimal, getcontext

class OpBehaviorFloatSqrtTest(unittest.TestCase):

    def test_evaluate_binary_long(self):
        op = OpBehaviorFloatSqrt()
        ff = FloatFormatFactory().get_float_format(8)
        longbits = ff.get_encoding(2.0)
        longbits = op.evaluate_unary(8, 8, longbits)
        d = ff.get_host_float(longbits)
        self.assertAlmostEqual("1.414213562373095", str(d).split('.')[0])

    def test_evaluate_binary_big_integer(self):
        op = OpBehaviorFloatSqrt()
        ff = FloatFormatFactory().get_float_format(8)
        big = ff.get_big_float(2.0)
        encoding = ff.get_encoding(big)
        encoding = op.evaluate_unary(8, 8, encoding)
        result = ff.get_host_float(encoding)
        self.assertAlmostEqual("1.414213562373095", str(ff.round(result)))

if __name__ == '__main__':
    unittest.main()
