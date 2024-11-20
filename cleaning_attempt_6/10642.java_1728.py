import threading
import time
from unittest import TestCase

class ExpiringSwingTimerTest(TestCase):

    def test_run_when_ready(self):
        wait_count = 2
        counter = [0]
        run_count = [0]

        def is_ready():
            return counter[0] > wait_count

        def r():
            nonlocal run_count
            run_count[0] += 1

        ExpiringSwingTimer.run_when(lambda: is_ready(), 10, lambda: r())

        time.sleep(11)
        self.assertGreater(counter[0], wait_count)
        self.assertEqual(run_count[0], 1)

    def test_run_when_ready_timeout(self):
        counter = [False]
        run_count = [False]

        def is_ready():
            return False

        ExpiringSwingTimer.run_when(lambda: is_ready(), 5, lambda: None)

        time.sleep(6)
        self.assertFalse(run_count[0])

    def test_work_only_happens_once(self):
        counter = [True]
        run_count = [0]

        def is_ready():
            return True

        ExpiringSwingTimer.run_when(lambda: is_ready(), 10, lambda: None)

        time.sleep(11)
        self.assertEqual(run_count[0], 1)


class ExpiringSwingTimer:
    @staticmethod
    def run_when(condition, timeout, action):
        threading.Thread(target=lambda: _run_when(condition, timeout, action)).start()

def _run_when(condition, timeout, action):
    while True:
        if condition():
            break
        time.sleep(0.1)
        if not ExpiringSwingTimer.is_running():
            return

    action()
