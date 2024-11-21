import unittest
from unittest.mock import patch, Mock
from camel_tools.producer_template import ProducerTemplate
from camel_tools.endpoint import Endpoint

class WireTapRouteTest(unittest.TestCase):

    @patch('camel_tools.producer_template.ProducerTemplate')
    def setUp(self, producer_template):
        self.entry = producer_template.return_value
        self.endpoint = Mock()
        self.wire_tap_endpoint = Mock()

    def test_wire_tap(self):
        self.entry.send_body("TEST")

        self.assertEqual(1, self.endpoint.expected_message_count)
        self.assertEqual(1, self.wire_tap_endpoint.expected_message_count)

        self.assertTrue(self.endpoint.is_satisfied())
        self.assertTrue(self.wire_tap_endpoint.is_satisfied())

        endpoint_in = self.endpoint.get_exchanges()[0].get_in().body
        wire_tap_endpoint_in = self.wire_tap_endpoint.get_exaches()[0].get_in().body

        self.assertEqual("TEST", endpoint_in)
        self.assertEqual("TEST", wire_tap_endpoint_in)

if __name__ == '__main__':
    unittest.main()
