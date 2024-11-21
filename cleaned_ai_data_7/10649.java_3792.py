import unittest
from threading import Thread
from time import sleep

class CountLatch:
    def __init__(self):
        self.count = 0

    def increment(self):
        self.count += 1

    def decrement(self):
        if self.count > 0:
            self.count -= 1

    def await(self, timeout=10.0):
        import time
        start_time = time.time()
        while True:
            if self.count == 0 or (time.time() - start_time) >= timeout:
                return False
            sleep(0.01)

class Test(unittest.TestCase):

    @unittest.skipIf(not hasattr(unittest, 'Test'), "This test is not supported in this Python version")
    def setUp(self):
        pass

    @unittest.skipIf(not hasattr(unittest, 'Test'), "This test is not supported in this Python version")
    def tearDown(self):
        pass

    def test_no_wait_initially(self):
        countLatch = CountLatch()
        self.assertFalse(countLatch.await())

    def test_waits_when_count_not_zero(self):
        countLatch = CountLatch()
        countLatch.increment()
        self.assertTrue(countLatch.await(timeout=10.0))

    def test_no_wait_when_count_incremented_then_decremented(self):
        countLatch = CountLatch()
        countLatch.increment()
        countLatch.decrement()
        self.assertFalse(countLatch.await())

    def test_waits_then_returns_when_count_decremented(self):
        start_event = threading.Event()
        done_event = threading.Event()
        countLatch = CountLatch()
        atomic_bool = [False]
        t = Thread(target=self.test_waits_then_returns_helper, args=(start_event, done_event, countLatch, atomic_bool))
        t.start()
        start_event.set()
        sleep(1.0)
        countLatch.decrement()
        done_event.wait()
        self.assertTrue(atomic_bool[0])

    def test_waits_then_returns_helper(self, start_event, done_event, countLatch, atomic_bool):
        try:
            start_event.wait()
            if not countLatch.await(timeout=10.0):
                atomic_bool[0] = True
        except KeyboardInterrupt as e:
            print("KeyboardInterrupt: ", e)
        finally:
            done_event.set()

if __name__ == '__main__':
    unittest.main()
