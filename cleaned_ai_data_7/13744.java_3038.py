import unittest

class TestInformationController(unittest.TestCase):

    def test_get_product_title(self):
        info_controller = InformationController()
        title = info_controller.get_product_title()
        self.assertEqual("The Product Title.", title)

if __name__ == '__main__':
    unittest.main()
