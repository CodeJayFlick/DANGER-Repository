Here is the equivalent Python code:

```Python
import unittest
from unittest.mock import patch

class AbstractTestJerseyRest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.database_adapter = DatabaseAdapter()

    @patch('org.projectnessie.jaxrs.NessieJaxRsExtension')
    def setUp(self, mock_extension):
        self.server = mock_extension.return_value
        self.server.get_uri.return_value = 'http://example.com'

    def test_something(self):
        # Your test code here

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@ExtendWith`, `@RegisterExtension` and other annotations. We are using Python's built-in unit testing framework, which is very different from JUnit.

In this example, we're creating a test class with an abstract method (`setUp`) to set up the environment for each test case. The `test_something` function can be replaced with your actual tests.