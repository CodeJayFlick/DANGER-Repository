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
