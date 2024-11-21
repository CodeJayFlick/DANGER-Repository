Here is the translation of the Java code to Python:
```
import unittest
from datetime import datetime

class SysTimeVersionControllerTest(unittest.TestCase):
    def test(self):
        version_controller = SysTimeVersionController.INSTANCE
        diff = version_controller.curr_version() - int(datetime.now().timestamp())
        # avoid test failure on a poor machine, bear 200ms difference here.
        self.assertTrue(-200 <= diff <= 200)
        diff = version_controller.next_version()
        try:
            time.sleep(0.2)  # equivalent to Thread.sleep(200)
            diff -= int(datetime.now().timestamp())
            self.assertTrue(-1000 <= diff <= -200)
        except KeyboardInterrupt:  # equivalent to InterruptedException
            pass

if __name__ == '__main__':
    unittest.main()
```
Note that I had to make some assumptions about the Python code, as there is no direct translation of Java's `Thread.sleep` and `InterruptedException`. In Python, we use the `time.sleep` function instead. Additionally, I used the `datetime` module to get the current timestamp in milliseconds.

Also, please note that this code assumes you have a `SysTimeVersionController` class with methods `curr_version()` and `next_version()`, which are not defined here. You would need to implement these classes or use existing ones to make this test run correctly.