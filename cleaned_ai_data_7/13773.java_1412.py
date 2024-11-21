import unittest

class TestPriceController(unittest.TestCase):

    def test_get_price(self):
        self.assertEqual("20", PriceController().get_price())

if __name__ == '__main__':
    unittest.main()
