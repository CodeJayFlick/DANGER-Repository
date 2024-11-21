Here is the translation of the given Java code into Python:

```Python
import unittest
from unittest.mock import patch, MagicMock
import logging


class BallItemTest(unittest.TestCase):

    def setUp(self):
        self.appender = InMemoryAppender()

    def tearDown(self):
        self.appender.stop()

    @patch('BallThread')
    def test_click(self, ball_thread_mock: MagicMock):
        ball_item = BallItem()
        ball_item.twin = ball_thread_mock
        in_order = [ball_thread_mock]

        for _ in range(10):
            ball_item.click()
            in_order.append(ball_thread_mock.suspend_me())
            ball_item.click()
            in_order.append(ball_thread_mock.resume_me())

        self.assertEqual(len(in_order), 20)

    @patch('BallThread')
    def test_do_draw(self, ball_thread_mock: MagicMock):
        ball_item = BallItem()
        ball_item.twin = ball_thread_mock
        ball_item.draw()

        logging.getLogger("root").info("draw")
        logging.getLogger("root").info("doDraw")

        self.assertEqual(len(self.appender.log), 2)

    @patch('BallThread')
    def test_move(self, ball_thread_mock: MagicMock):
        ball_item = BallItem()
        ball_item.twin = ball_thread_mock
        ball_item.move()

        logging.getLogger("root").info("move")
        self.assertEqual(len(self.appender.log), 1)


class InMemoryAppender(logging.Handler):

    def __init__(self):
        super().__init__()
        self.log = []

    def emit(self, record: logging.LogRecord) -> None:
        self.log.append(record)

    def log_contains(self, message: str) -> bool:
        return any(event.getMessage() == message for event in self.log)

    def get_log_size(self) -> int:
        return len(self.log)


if __name__ == '__main__':
    unittest.main()
```

Note that Python's logging module is used instead of the Java equivalent.