import unittest
from math import inf as positive_infinity, -inf as negative_infinity, nan as float_nan


class OpBehaviorFloatAbsTest(unittest.TestCase):

    def test_evaluate_binary_long(self):
        op = OpBehaviorFloatAbs()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = ff.get_encoding(2.5)
        result = op.evaluate_unary(8, 8, ff.op_abs(a))
        self.assertAlmostEqual(2.5, float(ff.get_host_float(result)))

        a = ff.get_encoding(-2.5)
        result = op.evaluate_unary(8, 8, a)
        self.assertAlmostEqual(2.5, float.ff.get_host_float(result))

        a = ff.get_encoding(positive_infinity)
        result = op.evaluate_unary(8, 8, a)
        self.assertEqual(float_nan, float(ff.get_host_float(result)))

        a = ff.get_encoding(negative_infinity)
        result = op.evaluate_unary(8, 8, a)
        self.assertEqual(float_nan, float.ff.get_host_float(result))

        a = ff.get_encoding(float_nan)
        result = op.evaluate_unary(8, 8, a)
        self.assertEqual(float_nan, float(ff.get_host_float(result)))


    def test_evaluate_binary_big_integer(self):
        op = OpBehaviorFloatAbs()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = ff.get_encoding(ff.get_big_float(2.5))
        result = op.evaluate_unary(8, 8, a)
        self.assertAlmostEqual(float.ff.get_host_float(result), float.ff.get_big_float(2.5))

        a = ff.get_encoding(ff.get_big_float(-2.5))
        result = op.evaluate_unary(8, 8, a)
        self.assertAlmostEqual(float.ff.get_host_float(result), float.ff.get_big_float(2.5))

        a = ff.get_big_infinity_encoding(False)
        result = op.evaluate_unary(8, 8, a)
        self.assertEqual(ff.get_big_infinity(False), float.ff.get_host_float(result))

        a = ff.get_big_infinity_encoding(True)
        result = op.evaluate_unary(8, 8, a)
        self.assertEqual(ff.get_big_infinity(False), float.ff.get_host_float(result))

        a = ff.get_big_nan_encoding(False)
        result = op.evaluate_unary(8, 8, a)
        self.assertEqual(ff.get_big_nan(False), float.ff.get_host_float(result))


if __name__ == '__main__':
    unittest.main()
