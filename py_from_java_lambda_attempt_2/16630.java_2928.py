Here is the translation of the Java code to Python:

```Python
import unittest
from thrift import TException
from thrift.protocol import TBinaryProtocol
from thrift.transport import TNonblockingSocket
from iotdb.cluster.client.async import AsyncMetaClientFactory
from iotdb.cluster.common import TestUtils
from iotdb.cluster.config import ClusterConfig, ClusterDescriptor

class TestAsyncMetaClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.is_async_server = ClusterDescriptor.getInstance().getConfig().is_use_async_server()
        ClusterDescriptor.getInstance().getConfig().set_use_async_server(True)

    @classmethod
    def tearDownClass(cls):
        ClusterDescriptor.getInstance().getConfig().set_use_async_server(cls.is_async_server)

    def test(self):

        async_client_pool = AsyncMetaClientFactory(AsyncMetaClientFactory())
        client = None

        node = TestUtils.get_node(0)
        client = AsyncMetaClient(
            AsyncMetaClientFactory(),
            TNonblockingSocket(node['internal_ip'], node['meta_port'], RaftServer.getConnection_timeout_in_ms()),
            new TBinaryProtocol()
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
        self.assertTrue(client.is_ready())

        self.assertEqual(str(client), "MetaClient{node=ClusterNode{'192.168.0.0', '9003', 0, '40010', '6667', '0.0.0.0'}}")

if __name__ == '__main__':
    unittest.main()
```

Please note that this is a Python translation of the Java code and may not be exactly equivalent due to differences in language syntax and semantics.