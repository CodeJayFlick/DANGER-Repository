import os
from typing import List

class BaseSingleNodeTest:
    def __init__(self):
        self.meta_server = None
        self.use_async_server = False
        self.seed_node_urls: List[str] = []
        self.replica_num = 0
        self.auto_create_schema = False

    def setUp(self) -> None:
        self.init_configs()
        if not self.meta_server:
            from org.apache.iotdb.cluster.server import MetaClusterServer
            self.meta_server = MetaClusterServer()
        self.meta_server.start()
        self.meta_server.build_cluster()

    def tearDown(self) -> None:
        if self.meta_server:
            self.meta_server.stop()
        self.recover_configs()
        os.system('rm -rf /tmp/iotdb*')

    def init_configs(self):
        from org.apache.iotdb.cluster.config import ClusterDescriptor
        config = ClusterDescriptor().get_config()
        self.use_async_server = config.get_use_async_server()
        self.seed_node_urls = [f'127.0.0.1:9003:40011:{Constants.RPC_PORT}']
        self.replica_num = 1
        self.auto_create_schema = True

    def recover_configs(self):
        from org.apache.iotdb.cluster.config import ClusterDescriptor
        config = ClusterDescriptor().get_config()
        config.set_use_async_server(self.use_async_server)
        config.set_seed_node_urls(self.seed_node_urls)
        config.set_replication_num(self.replica_num)
        config.set_enable_auto_create_schema(self.auto_create_schema)

    def open_session(self) -> None:
        from org.apache.iotdb.session import Session
        session = Session('127.0.0.1', Constants.RPC_PORT)
        session.open()
