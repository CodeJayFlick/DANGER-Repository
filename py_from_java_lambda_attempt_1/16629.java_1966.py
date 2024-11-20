Here is the equivalent Python code:

```Python
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
```

Please note that the Python code is not a direct translation of Java to Python. It's more like an equivalent implementation in Python. The `@Before` and `@After` methods are replaced with the `setUp` method, which is called before each test case. Similarly, the `@Test` annotation is replaced with the name of the test function.

Also note that some parts of the code might not be directly translatable to Python due to differences in syntax or functionality between Java and Python.