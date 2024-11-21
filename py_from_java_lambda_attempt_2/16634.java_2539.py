Here is the translation of the Java code into Python:

```Python
import unittest
from threading import Thread
from time import sleep

class SyncClientPoolTest(unittest.TestCase):

    def setUp(self):
        self.test_sync_client_factory = TestSyncClientFactory()

    def tearDown(self):
        self.test_sync_client_factory = None

    def test_test_client(self):
        sync_client_pool = SyncClientPool(self.test_sync_client_factory)
        for i in range(10):
            client = sync_client_pool.get_client(TestUtils.get_node(i))
            if isinstance(client, TestSyncClient):
                self.assertEqual(i, client.get_serial_num())

    def put_client(self):
        sync_client_pool = SyncClientPool(self.test_sync_client_factory)
        test_clients = []
        for i in range(10):
            client = sync_client_pool.get_client(TestUtils.get_node(i))
            test_clients.append(client)

        for i in range(10):
            sync_client_pool.put_client(TestUtils.get_node(i), test_clients[i])

        for i in range(10):
            pool_client = sync_client_pool.get_client(TestUtils.get_node(i))
            self.assertEqual(test_clients[i], pool_client)

    def test_put_bad_client(self):
        sync_client_pool = SyncClientPool(self.test_sync_client_factory)
        client = sync_client_pool.get_client(TestUtils.get_node(0))
        client.input_protocol.transport.close()
        sync_client_pool.put_client(TestUtils.get_node(0), client)
        new_client = sync_client_pool.get_client(TestUtils.get_node(0))
        self.assertNotEqual(client, new_client)

    def test_max_client(self):
        max_client_num = ClusterDescriptor.getInstance().getConfig().getMaxClientPerNodePerMember()
        ClusterDescriptor.getInstance().getConfig().setMaxClientPerNodePerMember(5)
        sync_client_pool = SyncClientPool(self.test_sync_client_factory)

        for i in range(5):
            sync_client_pool.get_client(TestUtils.get_node(0))

        reference = AtomicReference(None)
        t = Thread(target=lambda: reference.set(sync_client_pool.get_client(TestUtils.get_node(0))))
        t.start()
        t.interrupt()
        self.assertIsNone(reference.get())
        ClusterDescriptor.getInstance().getConfig().setMaxClientPerNodePerMember(max_client_num)

    def test_wait_client(self):
        max_client_per_node_per_member = ClusterDescriptor.getInstance().getConfig().getMaxClientPerNodePerMember()

        try:
            ClusterDescriptor.getInstance().getConfig().setMaxClientPerNodePerMember(10)
            sync_client_pool = SyncClientPool(self.test_sync_client_factory)

            node = TestUtils.get_node(0)
            clients = []

            for i in range(10):
                client = sync_client_pool.get_client(node)
                clients.append(client)

            wait_start = AtomicBoolean(False)
            t = Thread(target=lambda: [wait_start.set(True), 
                                       synchronized(sync_client_pool): 
                                            for client in clients:
                                                sync_client_pool.put_client(node, client)])
            t.start()

            with synchronized(sync_client_pool):
                wait_start.set(True)
                client = sync_client_pool.get_client(node)

            self.assertIsNotNone(client)
        finally:
            ClusterDescriptor.getInstance().getConfig().setMaxClientPerNodePerMember(max_client_per_node_per_member)

    def test_wait_client_timeout(self):
        max_client_per_node_per_member = ClusterDescriptor.getInstance().getConfig().getMaxClientPerNodePerMember()

        try:
            ClusterDescriptor.getInstance().getConfig().setMaxClientPerNodePerMember(1)
            sync_client_pool = SyncClientPool(self.test_sync_client_factory)

            node = TestUtils.get_node(0)
            clients = []

            for i in range(2):
                client = sync_client_pool.get_client(node)
                clients.append(client)

            self.assertNotEqual(clients[0], clients[1])
        finally:
            ClusterDescriptor.getInstance().getConfig().setMaxClientPerNodePerMember(max_client_per_node_per_member)


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Before` and `@After`. In the above code, I used Python's built-in unit testing framework (`unittest`) to achieve similar functionality.