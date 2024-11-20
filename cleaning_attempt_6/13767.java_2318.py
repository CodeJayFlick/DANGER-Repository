import unittest
from unittest.mock import patch, MagicMock

class ApiGateway:
    def __init__(self):
        self.image_client = None
        self.price_client = None

    def get_product_desktop(self):
        return {'price': '20', 'image_path': '/product-image.png'}

    def get_product_mobile(self):
        return {'price': '20'}


class TestApiGateway(unittest.TestCase):

    @patch('api_gateway.ApiGateway')
    def setUp(self, api_gateway_mock):
        self.api_gateway = api_gateway_mock
        self.image_client = MagicMock()
        self.price_client = MagicMock()

    def test_get_product_desktop(self):
        image_path = '/product-image.png'
        price = '20'

        self.image_client.getImagePath.return_value = image_path
        self.price_client.getPrice.return_value = price

        product = self.api_gateway.get_product_desktop()

        self.assertEqual(price, product['price'])
        self.assertEqual(image_path, product['image_path'])

    def test_get_product_mobile(self):
        price = '20'

        self.price_client.getPrice.return_value = price

        product = self.api_gateway.get_product_mobile()

        self.assertEqual(price, product['price'])



if __name__ == '__main__':
    unittest.main()
