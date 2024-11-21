Here is the translation of the given Java code into Python:

```Python
import unittest
from unittest.mock import patch

class VariableStepGameLoopTest(unittest.TestCase):

    def setUp(self):
        self.game_loop = VariableStepGameLoop()

    def tearDown(self):
        self.game_loop = None

    @patch('VariableStepGameLoop.update')
    def test_update(self, mock_update):
        self.game_loop.update(20)
        self.assertEqual(self.game_loop.controller.get_bullet_position(), 0.01)

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@BeforeEach` and `@AfterEach`. Instead, we use the `setUp` method to initialize our test case before each test is run, and the `tearDown` method to release any resources after each test.