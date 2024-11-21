import unittest
from thrift import Thrift
from thrift.protocol import TBinaryProtocol
from thrift.transport import TSocket

class ClusterInfoServerTest(unittest.TestCase):

    def setUp(self):
        pass  # No setup needed in this case.

    def test_connect(self):
        try:
            transport = TSocket(IoTDBDescriptor.getInstance().getConfig().getRpcAddress(), 
                                  ClusterDescriptor.getInstance().getConfig().getClusterInfoRpcPort())
            transport.open()
        except Exception as e:
            self.fail(str(e))

        client = Thrift.Client(TBinaryProtocol(transport))
        self.assertIsNotNone(client)
        
        # Close the connection
        transport.close()

    def tearDown(self):
        pass  # No teardown needed in this case.

if __name__ == '__main__':
    unittest.main()
