import unittest
from typing import Optional

class LambdaEmbeddedServerTest(unittest.TestCase):
    def setUp(self):
        self.server = LambdaEmbeddedServer(None, None, None, False)

    def test_webSocket_configureWebSocket_noException(self):
        try:
            self.server.configureWebSockets(None, Optional[0])
        except Exception as e:
            print(str(e))
            self.fail()

if __name__ == '__main__':
    unittest.main()
