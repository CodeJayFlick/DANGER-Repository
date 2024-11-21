Here is the translation of the Java code to Python:

```Python
import socket
import threading
from thrift import TBinaryProtocolFactory
from thrift.protocol.TBinaryProtocol import TBinaryProtocol
from thrift.server import TSocketWrapper

class SyncDataClientTest:
    def test(self):
        node = {'internal_ip': 'localhost', 'data_port': 40010, 'client_ip': 'localhost'}
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', node['data_port']))
        server_socket.listen(1)

        listen_thread = threading.Thread(target=self.accept_connections, args=(server_socket,))
        listen_thread.start()

        try:
            sync_client_pool = SyncClientPool(FactorySync(new Factory()))
            client = sync_client_pool.get_client(node)
            self.assertEqual(client.node(), node)
            client.set_timeout(1000)
            self.assertEqual(client.timeout(), 1000)

            client.put_back()
            new_client = sync_client_pool.get_client(node)
            self.assertEqual(client, new_client)
            self.assertTrue(client.input_protocol().transport().is_open())

            print(f"DataClient{{node=ClusterNode{{ internal_ip='{node['internal_ip']}', meta_port=0," \
                  f" node_identifier=0, data_port={node['data_port']}, client_port=0, " \
                  f"client_ip='{node['client_ip']}'}}}")

            client = SyncDataClient(TBinaryProtocol(TSocketWrapper.wrap(node['internal_ip'], node['data_port'])))

            # client without a belong pool will be closed after put_back()
            client.put_back()
            self.assertFalse(client.input_protocol().transport().is_open())

        finally:
            server_socket.close()
            listen_thread.join()

    def test_try_close(self):
        node = {'internal_ip': 'localhost', 'data_port': 40010, 'client_ip': 'localhost'}
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', node['data_port']))
        server_socket.listen(1)

        listen_thread = threading.Thread(target=self.accept_connections, args=(server_socket,))
        listen_thread.start()

        try:
            sync_client_pool = SyncClientPool(FactorySync(new Factory()))
            client_out = None
            with (client_in := sync_client_pool.get_client(node)) as client_in:
                self.assertEqual(client_in.node(), node)
                client_in.set_timeout(1000)

            self.assertTrue(client_in.input_protocol().transport().is_open())

            with (new_client := sync_client_pool.get_client(node)) as new_client:
                self.assertEqual(client_out, new_client)
                print(f"DataClient{{node=ClusterNode{{ internal_ip='{node['internal_ip']}', meta_port=0," \
                      f" node_identifier=0, data_port={node['data_port']}, client_port=0, " \
                      f"client_ip='{node['client_ip']}'}}}")

            with (client_in := SyncDataClient(TBinaryProtocol(TSocketWrapper.wrap(node['internal_ip'], node['data_port'])))) as client_in:
                client_out = client_in

            # client without a belong pool will be closed after put_back()
            self.assertFalse(client_out.input_protocol().transport().is_open())

        finally:
            server_socket.close()
            listen_thread.join()

    def accept_connections(self, server_socket):
        while not threading.current_thread().interrupted():
            try:
                connection = server_socket.accept()
            except socket.error as e:
                return
```

Note that this code is a direct translation of the Java code and may need to be adjusted for Python's syntax and semantics.