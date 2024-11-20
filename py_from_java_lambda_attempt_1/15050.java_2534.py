Here is the translation of the given Java code into Python:

```Python
import unittest
from unittest.mock import patch
from io import StringIO

class DragonSlayingStrategyTest(unittest.TestCase):

    def setUp(self):
        self.appender = InMemoryAppender()

    def tearDown(self):
        self.appender.stop()

    @patch('sys.stdout', new_callable=StringIO)
    def test_execute(self, mock_stdout, strategy, expected_result):
        strategy.execute()
        self.assertEqual(expected_result, mock_stdout.getvalue().strip())
        self.assertEqual(1, len(mock_stdout.getvalue().split('\n')))

class InMemoryAppender:
    def __init__(self):
        logger = logging.getLogger('root')
        logger.addHandler(self)
        self.start()

    def append(self, eventObject):
        pass

    def get_log_size(self):
        return 0

    def get_last_message(self):
        return ''

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@BeforeEach` and `@AfterEach`. Instead, you can use the setup method provided by the unit testing framework.