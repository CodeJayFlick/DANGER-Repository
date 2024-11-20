import unittest
from time import time, sleep

class DelayedRemoteService:
    def __init__(self):
        pass

    def call(self):
        return "Delayed service is working"

class TestDelayedRemoteService(unittest.TestCase):

    @unittest.skip("Not implemented yet")
    def test_default_constructor(self):
        try:
            obj = DelayedRemoteService()
            obj.call()  # This will throw an exception
        except Exception as e:
            self.assertEqual(str(e), "No server available")

    @unittest.skip("Not implemented yet")
    def test_parameterized_constructor(self):
        start_time = time() - 2
        delay = 1

        try:
            obj = DelayedRemoteService()
            sleep(delay)
            result = obj.call()

            self.assertEqual(result, "Delayed service is working")

        except Exception as e:
            self.fail(str(e))

if __name__ == '__main__':
    unittest.main()
