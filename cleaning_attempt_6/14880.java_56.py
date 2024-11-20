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
