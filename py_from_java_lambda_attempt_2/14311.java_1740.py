Here is the equivalent Python code:

```Python
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
```

Please note that Python does not have a direct equivalent to Java's `@BeforeEach` and `@AfterEach`. Instead, you can use the `setUpClass` and `tearDownClass` methods for class-level setup and teardown. For method-level setup and teardown, you would typically put your code in the test function itself.

Also note that Python does not have a direct equivalent to Java's parameterized tests with different inputs. You could achieve this by writing separate test functions or using a testing framework like Behave or Pytest-Parametrize.