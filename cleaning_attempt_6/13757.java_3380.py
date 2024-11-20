import unittest
from random import randint

class RemoteService:
    def __init__(self, provider):
        self.provider = provider

    def do_remote_function(self, num):
        if randint(0, 1) == 0:  # simulate a failed call (50% chance)
            return "FAILURE"
        else:
            return str(num * 10)

class TestRemoteService(unittest.TestCase):

    @unittest.skip("Not implemented yet")
    def test_failed_call(self):
        provider = lambda: 0.21
        remote_service = RemoteService(provider)
        result = remote_service.do_remote_function(10)
        self.assertEqual(result, "FAILURE")

    @unittest.skip("Not implemented yet")
    def test_successful_call(self):
        provider = lambda: 0.2
        remote_service = RemoteService(provider)
        result = remote_service.do_remote_function(10)
        self.assertEqual(int(result), 100)

if __name__ == '__main__':
    unittest.main()
