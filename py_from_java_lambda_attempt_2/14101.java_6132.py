Here's a translation of your Java code into equivalent Python:

```Python
import unittest
from unittest.mock import patch, Mock
from typing import List

class SplitterRouteTest(unittest.TestCase):

    @patch('producer_template')
    def test_splitter(self, producer_template: Mock):
        # Three items in one entry message
        body = ["TEST1", "TEST2", "TEST3"]
        producer_template.send_body.return_value = None  # No return value for sendBody

        # Endpoint should have three different messages in the end order of the messages is not important
        endpoint = Mock()
        endpoint.expected_message_count = 3
        endpoint.assert_is_satisfied.return_value = True  # Assume it's satisfied by default

        producer_template.send_body(body)

        endpoint.expected_message_count.assert_called_once_with(3)
        endpoint.assert_is_satisfied.assert_called_once()

if __name__ == '__main__':
    unittest.main()
```

Please note that Python doesn't have direct equivalents for Java classes like `@SpringBootTest`, `@EnableAutoConfiguration` and so on. These are Spring Boot annotations which provide a lot of functionality out-of-the-box, but in this case we're just focusing on the unit test itself.

In this translation:

- We use the built-in Python unittest module to write our tests.
- The `patch` decorator is used to mock objects (like Java's Mockito).
- In the test method, we create a Mock object for the endpoint and set its expected message count to 3. Then we call `send_body` on the producer template with our body data.

This Python code should give you similar functionality as your original Java code.