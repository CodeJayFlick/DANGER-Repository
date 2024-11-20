Here is the translation of the Java code into Python:

```Python
import logging
from thrift import Thrift
from thrift.protocol import TBinaryProtocol, TCompactProtocol
from thrift.server import TServer
from thrift.transport import TTransport
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from queue import Queue

class ClientServer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.coordinator = None
        self.query_context_map = {}

    def set_coordinator(self, coordinator):
        self.coordinator = coordinator

    def start(self):
        if not hasattr(self, 'server_service'):
            server_service = ThreadPoolExecutor(max_workers=1)
            protocol_factory = TCompactProtocol.T Compact ProtocolFactory() if IoTDBDescriptor.getInstance().getConfig().isRpcThriftCompressionEnable() else TBinaryProtocol.T BinaryProtocolFactory()
            transport = TTransport.TSocket(InetSocketAddress(IoTDBDescriptor.getInstance().getConfig().getRpcAddress(), ClusterConfig.getClusterRpcPort()))
            pool_args = {'minWorkerThreads': CommonUtils.getCpuCores(), 'maxWorkerThreads': math.max(CommonUtils.getCpuCores(), ClusterConfig.getMaxConcurrentClientNum()), 'stopTimeoutVal': 0, 'stopTimeoutUnit': None}
            pool_server = TThreadPoolServer(pool_args)
            server_service.submit(lambda: pool_server.serve())
            self.logger.info("Client service is set up")

    def stop(self):
        if hasattr(self, 'server_service'):
            self.server_service.shutdown()
            transport.close()

    def execute_non_query_plan(self, plan):
        try:
            plan.check_integrity()
            if not (isinstance(plan, SetSystemModePlan) or isinstance(plan, FlushPlan)) and IoTDBDescriptor.getInstance().getConfig().isReadOnly():
                raise QueryProcessException("Current system mode is read-only, does not support non-query operation")
        except QueryProcessException as e:
            self.logger.warn(f"Illegal plan detected: {plan}")
            return RpcUtils.getStatus(TSStatusCode.EXECUTE_STATEMENT_ERROR, str(e))
        return self.coordinator.execute_non_query_plan(plan)

    def handle_client_exit(self):
        # release resources when a client disconnects
        pass

    def gen_query_context(self, query_id, debug, start_time, statement, timeout):
        context = RemoteQueryContext(query_id, debug, start_time, statement, timeout)
        self.query_context_map[query_id] = context
        return context

    def release_query_resource(self, query_id):
        # release resources locally and remotely
        super.release_query_resource(query_id)
        if query_id in self.query_context_map:
            context = self.query_context_map.pop(query_id)
            for queried_node in context.get_queried_nodes_map().values():
                handler = GenericHandler(Void(), AtomicReference())
                try:
                    async_data_client = coordinator.get_async_data_client(queried_node, RaftServer.get_read_operation_timeout_ms()) if ClusterDescriptor.getInstance().getConfig().is_use_async_server() else None
                    end_query(header=header, node=self.coordinator.get_this_node(), query_id=query_id, handler=handler)
                except TException as e:
                    # the connection may be broken, close it to avoid being reused
                    transport.close()
                    raise e

class RemoteQueryContext:
    def __init__(self, query_id, debug, start_time, statement, timeout):
        self.query_id = query_id
        self.debug = debug
        self.start_time = start_time
        self.statement = statement
        self.timeout = timeout

    @property
    def queried_nodes_map(self):
        # return the map of queried nodes and their corresponding handlers
        pass

class GenericHandler:
    def __init__(self, node, atomic_reference):
        self.node = node
        self.atomic_reference = atomic_reference

# usage example
client_server = ClientServer()
coordinator = Coordinator()  # initialize coordinator instance
client_server.set_coordinator(coordinator)
client_server.start()

try:
    plan = PhysicalPlan()  # create a physical plan
    status = client_server.execute_non_query_plan(plan)  # execute the non-query plan

except QueryProcessException as e:
    self.logger.error(f"Query failed: {e}")

finally:
    client_server.stop()
```

Please note that this is just one possible translation of the Java code into Python, and there may be other ways to achieve the same result.