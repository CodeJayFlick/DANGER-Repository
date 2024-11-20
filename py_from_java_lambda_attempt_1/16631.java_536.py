Here is the equivalent Python code:

```Python
import unittest
from thrift.protocol import TBinaryProtocol
from thrift.server import AsyncProcessors
from iotdb.cluster.config import ClusterConfig
from iotdb.cluster.common import TestUtils
from raft_service.thrift import RaftService


class TestAsyncMetaHeartbeatClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.is_async_server = True

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.config = ClusterConfig()
        self.is_async_server = self.config.use_async_server
        self.config.use_async_server = True

    def tearDown(self):
        self.config.use_async_server = self.is_async_server

    def test(self):
        factory_async = FactoryAsync(TBinaryProtocol.Factory())
        async_client = factory_async.get_async_client(TestUtils.get_node(0), None)
        self.assertEqual(
            "AsyncMetaHeartbeatClient{node=Node(internal_ip='192.168.0.0', meta_port=9003, node_identifier=0, data_port=40010, client_port=6667, client_ip='0.0.0.0'),meta_heartbeat_port=9004}",
            str(async_client)
        )


if __name__ == '__main__':
    unittest.main()
```

Please note that this is a Python translation of the Java code you provided and may not be an exact equivalent as some parts might have been simplified or modified to fit into Python's syntax.