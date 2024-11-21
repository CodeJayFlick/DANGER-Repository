Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from typing import Optional

class LambdaEmbeddedServerTest(unittest.TestCase):
    def setUp(self):
        self.server = LambdaEmbeddedServer(None, None, None, False)

    def test_webSocket_configureWebSocket_noException(self):
        try:
            self.server.configureWebSockets(None, Optional[0])
        except Exception as e:
            print(str(e))
            self.fail()

if __name__ == '__main__':
    unittest.main()
```

Note: Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the `unittest.TestCase` class and define test methods using standard method naming convention (i.e., those that start with "test"). The `setUp` method is used to initialize any necessary objects or resources for each test.