import socket
import threading
from unittest import TestCase

class Node:
    def __init__(self):
        self.meta_port = 9003
        self.internal_ip = "localhost"
        self.client_ip = "localhost"

    def set_meta_port(self, port):
        self.meta_port = port

    def get_meta_port(self):
        return self.meta_port


def start_server(node):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((node.internal_ip, node.get_meta_port() + 1))
    server_socket.listen(5)

    listen_thread = threading.Thread(target=listen_for_connections, args=(server_socket,))
    listen_thread.start()

def listen_for_connections(server_socket):
    while True:
        try:
            connection = server_socket.accept()
        except socket.error as e:
            return
        else:
            # Handle the accepted connection here
            pass


class SyncMetaHeartbeatClientTest(TestCase):

    def test(self):
        node = Node()
        node.set_meta_port(9003)
        start_server(node)

        try:
            factory_async = FactorySync(new_factory())
            sync_client = factory_async.get_sync_client(node, None)
            self.assertEqual(
                "SyncMetaHeartbeatClient{node=Node(internalIp=localhost, metaPort=9003," +
                " nodeIdentifier=0, dataPort=0, clientPort=0, clientIp=localhost),metaHeartbeatPort=9004}",
                str(sync_client))
        finally:
            server_socket.close()
            listen_thread.join()


if __name__ == "__main__":
    unittest.main()

