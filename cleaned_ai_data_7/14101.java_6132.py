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
