Here is the translation of the given Java code into Python:

```Python
import unittest

class DomesticTaxCalculator:
    def calculate(self, amount):
        return 0.2 * amount


class TestDomesticTaxCalculator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.target = DomesticTaxCalculator()

    def test_tax_calculation(self):
        tax = self.target.calculate(100)
        self.assertEqual(tax, 20)


if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we use the `unittest` framework and define test cases as methods of a class that inherits from `unittest.TestCase`. The `setUpClass` method is used to initialize an instance of our calculator before each test case runs.