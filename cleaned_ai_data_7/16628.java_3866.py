import unittest
from thrift import TException
from thrift.protocol import TBinaryProtocol
from thrift.transport import TSocket, TNonblockingTransport
from iotdb.cluster.common.TestUtils import TestUtils
from iotdb.cluster.config.ClusterConfig import ClusterConfig
from iotdb.cluster.config.ClusterDescriptor import ClusterDescriptor

class AsyncDataClientTest(unittest.TestCase):

    def setUp(self):
        self.is_async_server = ClusterConfig().is_use_async_server()
        ClusterConfig().set_use_async_server(True)

    def tearDown(self):
        ClusterConfig().set_use_async_server(self.is_async_server)

    def test(self):
        async_client_pool = AsyncClientPool(SingleManagerFactory(TBinaryProtocol.Factory()))
        client = None
        node = TestUtils.get_node(0)
        if client is None:
            client = AsyncDataClient(
                TBinaryProtocol.Factory(),
                TAsyncClientManager(),
                TNonblockingTransport(node.get_internal_ip(), node.get_data_port(), RaftServer().get_connection_timeout_in_ms())
            )
            self.assertTrue(client.is_ready())

        client = async_client_pool.get_client(TestUtils.get_node(0))
        self.assertEqual(client.get_node(), TestUtils.get_node(0))

        client.match_term(
            0,
            0,
            TestUtils.get_raft_node(0, 0),
            lambda aBoolean: None
        )
        self.assertFalse(client.is_ready())

        client.on_error(Exception())
        self.assertIsNone(client.get_curr_method())
        self.assertFalse(client.is_ready())

        self.assertEqual(
            "DataClient{node=ClusterNode{ internalIp='192.168.0.0', metaPort=9003, nodeIdentifier=0, dataPort=40010, clientPort=6667, clientIp='0.0.0.0'}}",
            str(client)
        )


if __name__ == '__main__':
    unittest.main()
