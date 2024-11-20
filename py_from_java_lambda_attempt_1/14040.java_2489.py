Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from unittest.mock import patch

class SimpleWizardTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.appender = InMemoryAppender()

    @classmethod
    def tearDownClass(cls):
        cls.appender.stop()

    def test_smoke(self):
        with patch('SimpleWizard.smoke') as smoke_mock:
            simple_wizard = SimpleWizard()
            simple_wizard.smoke()
            self.assertEqual("SimpleWizard smoking OldTobyTobacco", self.appender.get_last_message())
            self.assertEqual(1, self.appender.get_log_size())

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@BeforeEach` and `@AfterEach`. In the above code, I used class methods to achieve similar functionality.