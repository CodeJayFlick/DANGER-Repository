Here is the equivalent Python code:

```Python
import unittest
from unittest.mock import patch, mock_open, ANY
from time import sleep

class ProducerTest(unittest.TestCase):

    @patch('queue.Queue')
    def test_produce(self, queue):
        with patch('time.sleep', return_value=None) as mocked_sleep:
            producer = Producer("producer", queue)
            producer.produce()
            queue.put.assert_called_once_with(ANY)

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have direct equivalents to Java's `@Test` annotation or the JUnit Jupiter API. Instead, we use the built-in `unittest` module and its decorators (`@patch`, `@assert_called_once_with`) to achieve similar functionality.

Also note that I replaced the `Duration.ofMillis(6000)` with a simple call to `sleep()` in Python's equivalent of the test method.