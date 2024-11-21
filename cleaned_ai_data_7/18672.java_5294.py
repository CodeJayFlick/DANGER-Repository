import unittest
from datetime import datetime

class SlowAppTest(unittest.TestCase):

    def test_slow_app_init(self):
        slow_app = LambdaHandler()
        print("Start time:", slow_app.get_constructor_time())
        self.assertLess(slow_app.get_constructor_time(), 10000)
        req = AwsProxyRequestBuilder("/hello", "GET").build()
        start_request_time = datetime.now().timestamp()
        resp = slow_app.handle_request(req, MockLambdaContext())
        end_request_time = datetime.now().timestamp()
        self.assertGreater(end_request_time - start_request_time, SlowTestApplication.SlowDownInit.INIT_SLEEP_TIME_MS - 10000)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(MessageController.HELLO_MESSAGE, resp.body)

if __name__ == '__main__':
    unittest.main()
