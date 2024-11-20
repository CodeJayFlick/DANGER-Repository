import unittest
from thrift.protocol import TBinaryProtocol


class AsyncDataHeartbeatClientTest(unittest.TestCase):

    def setUp(self):
        self.config = ClusterConfig()
        self.is_async_server = self.config.use_async_server
        self.config.use_async_server = True

    def tearDown(self):
        self.config.use_async_server = self.is_async_server

    @unittest.skip("Not implemented yet")
    def test(self):
        factory_async = FactoryAsync(TBinaryProtocol.Factory())
        async_client = factory_async.get_async_client(0, None)
        # Add your assertions here
        pass


if __name__ == '__main__':
    unittest.main()
