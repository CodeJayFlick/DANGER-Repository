Here is the translation of the Java code to Python:
```
import thrift

class DataHeartbeatServer:
    def __init__(self, this_node, data_cluster_server):
        self.data_cluster_server = data_cluster_server
        super().__init__(this_node)

    def get_processor(self):
        if ClusterDescriptor.getInstance().get_config().is_use_async_server():
            return AsyncProcessor(data_cluster_server)
        else:
            return Processor(data_cluster_server)

    def get_heartbeat_server_socket(self) -> thrift.TServerTransport:
        if ClusterDescriptor.getInstance().get_config().is_use_async_server():
            return TNonblockingServerSocket(
                InetSocketAddress(ClusterUtils.get_internal_ip(), this_node.data_port + ClusterUtils.DATA_HEARTBEAT_PORT_OFFSET),
                self.get_connection_timeout_in_ms()
            )
        else:
            return TServerSocket(
                InetSocketAddress(ClusterUtils.get_internal_ip(), this_node.data_port + ClusterUtils.DATA_HEARTBEAT_PORT_OFFSET)
            )

    def get_client_thread_prefix(self):
        return "DataHeartbeatClientThread-"

    def get_server_client_name(self):
        return "DataHeartbeatServerThread-"
```
Note that I've used the `thrift` library to translate the Thrift-related code. You'll need to install this library using pip: `pip install thrift`. Additionally, you may need to modify the imports and class definitions depending on your specific use case.

Also, please note that Python is a dynamically-typed language, so I've omitted some type annotations for brevity. If you want to add explicit type hints, you can do so using the `typing` module.