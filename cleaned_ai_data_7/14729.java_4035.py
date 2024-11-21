import unittest
from unittest.mock import patch
from io import StringIO

class StewTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.appender = InMemoryAppender()

    @classmethod
    def tearDownClass(cls):
        cls.appender.stop()

    def setUp(self):
        self.appender.reset()
        self.stew = ImmutableStew(1, 2, 3, 4)

    def test_mix(self):
        expected_message = "Mixing the immutable stew we find: 1 potatoes, 2 carrots, 3 meat and 4 peppers"
        for _ in range(20):
            with patch('builtins.print') as mock_print:
                self.stew.mix()
                mock_print.assert_called_once_with(expected_message)
                self.assertEqual(self.appender.get_last_log(), expected_message)

    def test_get_log_size(self):
        self.assertEqual(self.appender.get_log_size(), 21)  # The log size should be 20 + the initial message

if __name__ == '__main__':
    unittest.main()
