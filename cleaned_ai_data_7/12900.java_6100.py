import unittest
from random import randint, uniform

class BigFloatTest(unittest.TestCase):
    def setUp(self):
        self.test_float_list = [float(x) for x in range(-1000, 1001)] + \
            [x / (10 ** i) for i in range(3)]
        self.test_double_list = [round(x, 15) for x in self.test_float_list]

    def test_ieee_float_representation(self):
        assertEqual("0b0.0", format(0.0f, "b"))
        assertEqual("0b1.0 * 2^0", format(1.0f, "b"))
        assertEqual("0b1.0 * 2^1", format(2.0f, "b"))
        assertEqual("0b1.0 * 2^-1", format(0.5f, "b"))
        assertEqual("-0b1.0 * 2^1", format(-2.0f, "b"))

    def test_ieee_float_as_big_float(self):
        for f in self.test_float_list:
            bf = BigFloat(f)
            assertEqual(format(bf, "b"), format(f, "b"))

    def test_ieee_double_representation(self):
        assertEqual("0b0.0", format(0.0, "b"))
        assertEqual("0b1.0 * 2^0", format(1.0, "b"))
        assertEqual("0b1.0 * 2^1", format(2.0, "b"))
        assertEqual("0b1.0 * 2^-1", format(0.5, "b"))
        assertEqual("-0b1.0 * 2^1", format(-2.0, "b"))

    def test_ieee_double_as_big_float(self):
        for d in self.test_double_list:
            bf = BigFloat(d)
            assertEqual(format(bf, "b"), format(d, "b"))

    def unary_op_test(self, op, bproc):
        for f in self.test_float_list:
            bf = BigFloat(f)
            result = op(f)
            bproc(bf)
            if not math.isnan(result):
                assertEqual(format(result, "b"), bf.to_binary_string())

    def binary_op_test(self, op, bproc):
        for fa in self.test_float_short_list:
            for fb in self.test_float_short_list:
                result = op(fa, fb)
                bf_a = BigFloat(fa)
                bf_b = BigFloat(fb)
                bproc(bf_a, bf_b)
                if not math.isnan(result):
                    assertEqual(format(result, "b"), bf_a.to_binary_string())

    def test_float_add(self):
        self.binary_op_test(lambda a, b: a + b, lambda a, b: a.add(b))

    def test_float_subtract(self):
        self.binary_op_test(lambda a, b: a - b, lambda a, b: a.sub(b))

    def test_float_multiply(self):
        self.binary_op_test(lambda a, b: a * b, lambda a, b: a.mul(b))

    def test_float_divide(self):
        self.binary_op_test(lambda a, b: a / b if b != 0 else float('inf'), lambda a, b: a.div(b) if b != 0 else BigFloat(float('inf')))

    def test_double_add(self):
        self.binary_op_test(lambda a, b: a + b, lambda a, b: a.add(b))

    def test_double_subtract(self):
        self.binary_op_test(lambda a, b: a - b, lambda a, b: a.sub(b))

    def test_double_multiply(self):
        self.binary_op_test(lambda a, b: a * b, lambda a, b: a.mul(b))

    def test_double_divide(self):
        self.binary_op_test(lambda a, b: a / b if b != 0 else float('inf'), lambda a, b: a.div(b) if b != 0 else BigFloat(float('inf')))

if __name__ == '__main__':
    unittest.main()
