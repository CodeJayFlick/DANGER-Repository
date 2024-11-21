import threading
import time
from unittest import TestCase

class TestThreadExceptionHandler(TestCase):

    def setUp(self):
        self.handler = threading.Thread().get_uncaught_exception_handler()
        threading.set_uncaught_exception_handler(TestExceptionHandler("Expected!"))
        self.count = 0

    def tearDown(self):
        threading.set_uncaught_exception_handler(self.handler)

    def test(self):
        num_threads = 10
        for i in range(num_threads):
            thread = TestThread()
            thread.start()

        time.sleep(0.5)
        self.assertEqual(num_threads, self.count)


class TestThread(threading.Thread):

    def run(self):
        raise RuntimeError("Expected!")


class TestExceptionHandler:

    def __init__(self, name):
        self.name = name

    def uncaught_exception(self, t, e):
        self.assertEqual(e.args[0], self.name)
        global count
        count += 1


count = 0
