Here is the translation of the Java code to Python:

```Python
class SyncDataHeartbeatClient:
    def __init__(self, protocol_factory, node, pool):
        super().__init__()
        self.node = node
        self.pool = pool
        transport = RpcTransportFactory().get_transport(
            TSocket(TConfigurationConst.default_t_configuration,
                    node.get_internal_ip(),
                    node.get_data_port() + ClusterUtils.DATA_HEARTBEAT_PORT_OFFSET,
                    RaftServer.get_heartbeat_client_conn_timeout_ms()))
        super().__init__(protocol_factory.get_protocol(transport))
        self.input_protocol.transport.open()

    def __str__(self):
        return f"SyncHeartbeatDataClient{{node={super().get_node()}, data_heartbeat_port={super().get_node().get_data_port() + ClusterUtils.DATA_HEARTBEAT_PORT_OFFSET}}}"

class FactorySync:
    def __init__(self, protocol_factory):
        self.protocol_factory = protocol_factory

    def get_sync_client(self, node, pool):
        return SyncDataHeartbeatClient(self.protocol_factory, node, pool)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of a class extending another. The equivalent code in Python is written as above.

Also note that Python does not require explicit type declarations like Java does.