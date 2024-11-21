import unittest
from unittest.mock import patch
from io import StringIO

class CommandTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.appender = InMemoryAppender()

    @classmethod
    def tearDownClass(cls):
        cls.appender.stop()

    @patch('builtins.print')
    def test_display(self, mock_print):
        front_controller = FrontController()
        self.assertEqual(0, len(self.appender.get_log()))
        front_controller.handle_request("Archer")
        self.assertEqual("Displaying archers", self.appender.get_last_message())
        self.assertEqual(1, len(self.appender.get_log()))

    @patch('builtins.print')
    def test_display_catapult(self, mock_print):
        front_controller = FrontController()
        self.assertEqual(0, len(self.appender.get_log()))
        front_controller.handle_request("Catapult")
        self.assertEqual("Displaying catapults", self.appender.get_last_message())
        self.assertEqual(1, len(self.appender.get_log()))

    @patch('builtins.print')
    def test_display_non_existent_command(self, mock_print):
        front_controller = FrontController()
        self.assertEqual(0, len(self.appender.get_log()))
        front_controller.handle_request("NonExistentCommand")
        self.assertEqual("Error 500", self.appender.get_last_message())
        self.assertEqual(1, len(self.appender.get_log()))


if __name__ == '__main__':
    unittest.main()
