Here is the equivalent Python code:

```Python
import unittest
from unittest.mock import patch, mock_open, call


class TestContentView(unittest.TestCase):

    @patch('com.iluwatar.flux.store.ContentStore')
    def test_store_changed(self, content_store):
        # Arrange
        content = 'PRODUCTS'
        content_store.return_value.get_content.return_value = content

        view = ContentView()

        # Act
        view.store_changed(content_store)

        # Assert
        self.assertEqual(content_store.return_value.get_content.call_count, 1)


if __name__ == '__main__':
    unittest.main()
```

Note: The original Java code uses Mockito for mocking and testing. In Python, we use the `unittest.mock` module to achieve similar functionality.