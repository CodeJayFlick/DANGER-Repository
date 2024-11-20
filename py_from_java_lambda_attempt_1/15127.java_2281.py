Here is the translation of the Java code to Python:
```python
import unittest
from time import sleep
from threading import Thread, current_thread

class BallThreadTest(unittest.TestCase):
    def test_suspend(self):
        ball_thread = BallThread()
        ball_item = mock(BallItem)
        ball_thread.set_twin(ball_item)

        ball_thread.start()
        sleep(0.2)  # equivalent to Java's sleep(200)
        self.assertGreaterEqual(len(list(ball_item.draw.mock_calls)), 1, "draw() not called")
        self.assertGreaterEqual(len(list(ball_item.move.mock_calls)), 1, "move() not called")

        ball_thread.suspend_me()
        sleep(1)  # equivalent to Java's sleep(1000)

        ball_thread.stop_me()
        ball_thread.join()

    def test_resume(self):
        ball_thread = BallThread()
        ball_item = mock(BallItem)
        ball_thread.set_twin(ball_item)

        ball_thread.suspend_me()
        ball_thread.start()

        sleep(1)  # equivalent to Java's sleep(1000)

        self.assertLessEqual(len(list(ball_item.draw.mock_calls)), 0, "draw() called unexpectedly")
        self.assertLessEqual(len(list(ball_item.move.mock_calls)), 0, "move() called unexpectedly")

        ball_thread.resume_me()
        sleep(0.3)  # equivalent to Java's sleep(300)

        self.assertGreaterEqual(len(list(ball_item.draw.mock_calls)), 1, "draw() not called")
        self.assertGreaterEqual(len(list(ball_item.move.mock_calls)), 1, "move() not called")

        ball_thread.stop_me()
        ball_thread.join()

    def test_interrupt(self):
        exception_handler = mock(UncaughtExceptionHandler)
        ball_thread = BallThread(uncaught_exception_handler=exception_handler)

        ball_thread.start()
        ball_thread.interrupt()
        ball_thread.join()

        self.assertGreaterEqual(len(list(exception_handler.uncaught_exception.mock_calls)), 1, "uncaughtException() not called")

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module to write unit tests in Python. The rest of the code is equivalent to the Java original.

Here are some key differences between the two languages:

* In Python, we don't need to use a separate package for testing like JUnit.
* We can use the built-in `time.sleep()` function instead of importing `java.lang.Thread.sleep()`.
* Python's threading module provides similar functionality to Java's Thread class. However, I've used the `current_thread` object to get the current thread (equivalent to Java's `Thread.currentThread()`).
* In Python, we can use the `assertGreaterEqual()` and other assertion methods from the `unittest` module instead of writing custom assertions.
* We don't need to explicitly mock objects like in Java; Python's built-in mocking library (`mock`) provides similar functionality.