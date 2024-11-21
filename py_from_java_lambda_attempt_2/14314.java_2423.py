Here is the equivalent Python code:

```Python
import unittest
from unittest.mock import patch
from io import StringIO

class ViewTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.appender = InMemoryAppender()

    @classmethod
    def tearDownClass(cls):
        cls.appender.stop()

    @patch('sys.stdout', new_callable=StringIO)
    def test_display(self, mock_stdout):
        views_and_messages = [
            (ArcherView(), "Displaying archers"),
            (CatapultView(), "Displaying catapults"),
            (ErrorView(), "Error 500")
        ]

        for view, message in views_and_messages:
            self.appender.reset()
            view.display()
            self.assertEqual(self.appender.get_log_size(), 1)
            self.assertEqual(mock_stdout.getvalue().strip(), message)

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have direct equivalents to Java's `@BeforeEach` and `@AfterEach`. Instead, we use the `setUpClass` method for class-level setup and teardown. The test itself uses a mock object (`sys.stdout`) to capture the output of the view objects.

Also note that I've used the `unittest.mock.patch` decorator to replace the standard output with our own StringIO object. This allows us to easily verify the expected messages in each test case.