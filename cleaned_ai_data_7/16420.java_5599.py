class SyncMetaHeartbeatClient:
    def __init__(self, protocol_factory, node, pool):
        super().__init__(protocol_factory.get_protocol(
            RpcTransportFactory().get_transport(TSocket(
                TConfigurationConst.default_tconfiguration,
                node.internal_ip(),
                node.meta_port() + ClusterUtils.META_HEARTBEAT_PORT_OFFSET,
                RaftServer.heartbeat_client_conn_timeout_ms()))))
        self.node = node
        self.pool = pool
        self.get_input_protocol().get_transport().open()

    class FactorySync:
        def __init__(self, protocol_factory):
            self.protocol_factory = protocol_factory

        def get_sync_client(self, node, pool):
            return SyncMetaHeartbeatClient(self.protocol_factory, node, pool)

    def __str__(self):
        return f"SyncMetaHeartbeatClient{{'node': {super().get_node()}, 'meta_heartbeat_port': {super().get_node().meta_port() + ClusterUtils.META_HEARTBEAT_PORT_OFFSET}}}"
