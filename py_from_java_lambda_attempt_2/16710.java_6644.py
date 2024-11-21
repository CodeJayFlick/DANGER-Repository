Here is the equivalent Python code:

```Python
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
```

Please note that Python's `unittest` module is used to write unit tests, and it does not support Java-style annotations like `@Before`, `@After`, etc. Instead, you would typically define a setup method (`setUp`) and teardown method (`tearDown`) in your test class.

Also, the code assumes that there are classes `IoTDBDescriptor` and `ClusterDescriptor` which seem to be related to Apache IoTDB configuration. These might need to be replaced with equivalent Python objects or mocks if they don't exist as-is.