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
