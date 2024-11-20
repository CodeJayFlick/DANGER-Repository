import logging
from thrift import TAsyncClientManager
from thrift.protocol import TProtocolFactory
from thrift.transport import TNonblockingTransport
from datetime import date

class AsyncMetaClient:
    def __init__(self, protocol_factory: TProtocolFactory, client_manager: TAsyncClientManager, transport: TNonblockingTransport):
        self._logger = logging.getLogger(__name__)
        self.node = None
        self.pool = None
        super().__init__(protocol_factory, client_manager, transport)

    @property
    def node(self) -> Node:
        return self._node

    @node.setter
    def node(self, value: Node):
        self._node = value

    @property
    def pool(self) -> AsyncClientPool:
        return self._pool

    @pool.setter
    def pool(self, value: AsyncClientPool):
        self._pool = value

    def on_complete(self):
        super().on_complete()
        if self.pool is not None:
            self.pool.put_client(self.node, self)
            self.pool.on_complete(self.node)

    def on_error(self, e: Exception):
        super().on_error(e)
        self.pool.recreate_client(self.node)
        # TODO: if e instance of network failure
        self.pool.on_error(self.node)

class FactoryAsync:
    def __init__(self, protocol_factory: TProtocolFactory):
        self.protocol_factory = protocol_factory

    def get_async_client(self, node: Node, pool: AsyncClientPool) -> RaftService.AsyncClient:
        manager = managers[client_cnt.incrementAndGet() % len(managers)]
        return AsyncMetaClient(protocol_factory=self.protocol_factory,
                                client_manager=manager if manager is not None else TAsyncClientManager(),
                                node=node,
                                pool=pool)

    def __str__(self):
        return f"MetaClient{{node={self.node}}}"

def close(self):
    self._transport.close()
    self._current_method = None

class AsyncMetaClientFactory:
    pass
