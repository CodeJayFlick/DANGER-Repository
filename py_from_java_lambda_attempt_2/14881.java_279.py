Here is the equivalent Python code:

```Python
import unittest

class ForeignTaxCalculator:
    def calculate(self, amount):
        return amount * 0.6


class TestForeignTaxCalculator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.target = ForeignTaxCalculator()

    def test_tax_calculation(self):
        tax = self.target.calculate(100)
        self.assertEqual(tax, 60)


if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `package` statement. Instead, you can use modules or packages in Python. The above code is written as if it were part of the same module/file for simplicity.