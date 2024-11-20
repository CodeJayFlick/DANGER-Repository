Here is the translation of the Java code to Python:
```
import unittest
from unittest.mock import patch, Mock

class AggregatorTest(unittest.TestCase):
    def setUp(self):
        pass  # No need for setup in this case

    @patch('information_client.getProductTitle')
    @patch('inventory_client.getProductInventories')
    def test_get_product(self, inventory_client_mock, information_client_mock):
        title = "The Product Title."
        inventories = 5
        product_title_result = Mock(return_value=title)
        product_inventories_result = Mock(return_value=inventories)

        information_client_mock.return_value = product_title_result
        inventory_client_mock.return_value = product_inventories_result

        aggregator = Aggregator()  # Assuming an Aggregator class exists
        test_product = aggregator.get_product()

        self.assertEqual(title, test_product.title)
        self.assertEqual(inventories, test_product.product_inventories)

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module to write a Python unit test. The `@patch` decorator is used to mock out the dependencies (`information_client` and `inventory_client`) in the same way as Mockito's `when()` method.

Also, since there is no equivalent of Java's `@InjectMocks` annotation in Python, I've simply created an instance of the `Aggregator` class manually.