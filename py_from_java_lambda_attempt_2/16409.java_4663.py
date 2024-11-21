Here is the translation of the given Java code into equivalent Python:

```Python
import logging
from thrift import TProtocolFactory
from thrift.async import TAsyncClientManager
from thrift.transport import TNonblockingTransport
from thrift.protocol import TCompactProtocol
from thrift.server import AsyncProcessPool
from iotdb.cluster.config import ClusterDescriptor

class AsyncDataClient:
    def __init__(self, protocol_factory: TProtocolFactory,
                 client_manager: TAsyncClientManager,
                 node: dict, pool: 'AsyncClientPool'):
        self.node = node
        self.pool = pool
        super().__init__(protocol_factory, client_manager)

    async def on_complete(self):
        await super().on_complete()
        if self.pool:
            self.pool.put_client(self.node, self)
            self.pool.on_complete(self.node)

    async def on_error(self, e: Exception):
        await super().on_error(e)
        if self.pool:
            self.pool.recreate_client(self.node)
            # TODO: handle network failure
            self.pool.on_error(self.node)

    def close(self):
        self._transport.close()
        self._current_method = None

class AsyncClientPool:
    pass  # You need to implement this class yourself.

class FactoryAsync(TProtocolFactory):
    def __init__(self, protocol_factory: TProtocolFactory):
        self.protocol_factory = protocol_factory

    async def get_async_client(self, node: dict, pool: 'AsyncClientPool') -> AsyncDataClient:
        manager = await TAsyncClientManager()
        return AsyncDataClient(self.protocol_factory, manager, node, pool)

class SingleManagerFactory(TProtocolFactory):
    def __init__(self, protocol_factory: TProtocolFactory):
        self.protocol_factory = protocol_factory
        if ClusterDescriptor.getInstance().getConfig().isUseAsyncServer():
            try:
                self.manager = await TAsyncClientManager()
            except Exception as e:
                logging.error("Cannot init manager of SingleThreadFactoryAsync", e)

    async def get_async_client(self, node: dict, pool: 'AsyncClientPool') -> AsyncDataClient:
        return AsyncDataClient(self.protocol_factory, self.manager, node, pool)
```

Please note that the translation is not perfect and some parts might be missing or simplified.