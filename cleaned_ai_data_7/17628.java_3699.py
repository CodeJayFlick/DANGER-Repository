import logging
from thrift import TProcessor
from thrift.protocol import TBinaryProtocolFactory, TCompactProtocolFactory
from thrift.server import TServer, TThreadPoolServer
from thrift.transport import TTransportException
from thrift.transport.TSocket import TServerSocket

class ThriftServiceThread:
    def __init__(self,
                 processor: TProcessor,
                 service_name: str,
                 threads_name: str,
                 bind_address: str,
                 port: int,
                 max_worker_threads: int,
                 timeout_ms: int,
                 server_event_handler: callable,
                 compress: bool):
        self.service_name = service_name
        if compress:
            protocol_factory = TCompactProtocolFactory()
        else:
            protocol_factory = TBinaryProtocolFactory()

        try:
            transport = open_transport(bind_address, port)
            pool_args = {
                'processor': processor,
                'protocol_factory': protocol_factory,
                'transport_factory': RpcTransportFactory(),
                'max_worker_threads': max_worker_threads
            }
            server = TThreadPoolServer(pool_args)
            server.set_server_event_handler(server_event_handler)

        except TTransportException as e:
            close()
            if thread_stop_latch is not None and thread_stop_latch.count == 1:
                thread_stop_latch.count_down()

    def open_transport(self, bind_address: str, port: int) -> TServerSocket:
        max_retry = 5
        retry_interval_ms = 5000
        last_exp = None

        for i in range(max_retry):
            try:
                return TServerSocket(InetSocketAddress(bind_address, port))
            except TTransportException as e:
                last_exp = e
                time.sleep(retry_interval_ms)

        raise last_exp

    def set_thread_stop_latch(self, thread_stop_latch: 'CountDownLatch'):
        self.thread_stop_latch = thread_stop_latch

    def run(self):
        logging.info(f"The {self.service_name} service thread begin to run...")
        try:
            server.serve()
        except Exception as e:
            raise RPCServiceException(
                f"{IoTDBConstant.GLOBAL_DB_NAME}: {self.service_name} exit, because "
            ) from e
        finally:
            close()
            if self.thread_stop_latch is not None and self.thread_stop_latch.count == 1:
                self.thread_stop_latch.count_down()

    def close(self):
        if server is not None:
            server.set_should_stop(True)
            server.stop()
            server = None

        if transport is not None:
            transport.close()
            transport = None

    @property
    def is_serving(self) -> bool:
        return server.is_serving() if server else False


class RPCServiceException(Exception):
    pass


IoTDBConstant.GLOBAL_DB_NAME  # This should be replaced with your actual constant name.
