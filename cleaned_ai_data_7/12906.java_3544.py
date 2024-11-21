import unittest

class OpBehaviorBoolOrTest(unittest.TestCase):

    def test_evaluate_binary_long(self):
        op = OpBehaviorBoolOr()
        self.assertEqual(0, op.evaluate_binary(1, 1, 0, 0))
        self.assertEqual(1, op.evaluate_binary(1, 1, 0, 1))
        self.assertEqual(1, op.evaluate_binary(1, 1, 1, 0))
        self.assertEqual(1, op.evaluate_binary(1, 1, 1, 1))

    def test_evaluate_binary_big_integer(self):
        op = OpBehaviorBoolOr()
        self.assertEqual(0, op.evaluate_binary(1, 1, 0, 0))
        self.assertEqual(1, op.evaluate_binary(1, 1, 0, 1))
        self.assertEqual(1, op.evaluate_binary(1, 1, 1, 0))
        self.assertEqual(1, op.evaluate_binary(1, 1, 1, 1))

if __name__ == '__main__':
    unittest.main()
