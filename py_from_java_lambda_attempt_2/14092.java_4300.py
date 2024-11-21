Here is the equivalent Python code:

```Python
import unittest
from unittest.mock import patch, Mock

class AggregatorRouteTest(unittest.TestCase):

    @patch('AggregatorRouteTest.entry')
    def test_splitter(self, entry):
        # Three items in one entry message
        entry.send_body.return_value = None  # Replace with actual implementation if needed
        for _ in range(5):  # Send five messages instead of four as per the original code
            entry.send_body("TEST" + str(_+1))

        # Endpoint should have three different messages in the end order of the messages is not important
        endpoint = Mock()
        endpoint.expected_message_count.return_value = 2
        endpoint.assert_is_satisfied.return_value = None

        self.assertEqual(3, (entry.send_body("TEST" + str(4)).get_in().get_body()).split(";").length)
        self.assertEqual(2, (entry.send_body("TEST" + str(5)).get_in().get_body()).split(";").length)

if __name__ == '__main__':
    unittest.main()
```

Please note that this Python code is a translation of the original Java code and might not be exactly equivalent. The `@EndpointInject` annotation in Java does not have an exact counterpart in Python, so I used the `patch` decorator from the `unittest.mock` module to mock out the `entry` object.