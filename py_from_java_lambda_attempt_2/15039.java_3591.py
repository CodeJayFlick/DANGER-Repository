Here is the translation of the given Java code into Python:

```Python
import unittest

class OldArithmetic:
    def __init__(self):
        self.source = None  # Assuming this should be an instance variable

    def sum(self, *args):
        return sum(args)

    def mul(self, *args):
        result = 1
        for arg in args:
            result *= arg
        return result


class TestOldArithmetic(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.arithmetic = OldArithmetic()

    def test_sum(self):
        self.assertEqual(0, self.arithmetic.sum(-1, 0, 1))

    def test_mul(self):
        self.assertEqual(0, self.arithmetic.mul(-1, 0, 1))


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we use the `unittest` module and its decorators (`@classmethod`, `@staticmethod`) to define test cases.