Here is the translation of the Java code to Python:
```
import unittest
from datetime import datetime

class AsyncInitializationWrapperTest(unittest.TestCase):

    def test_init_create_no_start_time_sets_current_time(self):
        init = AsyncInitializationWrapper()
        start_time = int(datetime.now().timestamp())
        self.assertEqual(start_time, init.get_actual_start_time_ms())

    def test_init_create_with_start_time_stores_custom_start_time(self):
        start_time = int(datetime.now().timestamp())
        import time
        time.sleep(0.5)  # equivalent to Thread.sleep(500)
        init = AsyncInitializationWrapper(start_time)

        self.assertEqual(start_time, init.get_actual_start_time_ms())

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module for writing unit tests in Python, and the `datetime` module to work with dates and times. The rest of the code is straightforward translation from Java to Python.

Also, please note that this code assumes you have a class called `AsyncInitializationWrapper` defined elsewhere in your Python program, which has a method called `get_actual_start_time_ms()` that returns the actual start time as an integer (in milliseconds).