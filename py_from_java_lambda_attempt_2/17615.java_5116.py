Here is the translation of the given Java code into Python:

```Python
import logging
from threading import Thread
from socket import socket, AF_INET, SOCK_STREAM
from time import sleep

class MetricsService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.mbean_name = f"{IoTDBConstant.IOTDB_PACKAGE}:{IoTDBConstant.JMX_TYPE}={self.get_id().jmx_name}"
        self.server = None
        self.executor_service = None

    @classmethod
    def get_instance(cls):
        return MetricsServiceHolder.INSTANCE

    def get_id(self):
        return ServiceType.METRICS_SERVICE

    def get_metrics_port(self):
        config = IoTDBDescriptor.get_instance().get_config()
        return config.metrics_port

    def start(self):
        try:
            JMXService.register_mbean(MetricsService.get_instance(), self.mbean_name)
            self.start_service()
        except Exception as e:
            self.logger.error(f"Failed to start {self.get_id().name} because: {e}")
            raise StartupException(self.get_id().name, str(e))

    def stop(self):
        self.stop_service()
        JMXService.deregister_mbean(self.mbean_name)

    def start_service(self):
        if not IoTDBDescriptor.get_instance().get_config().enable_metric_service:
            return

        self.logger.info(f"{IoTDBConstant.GLOBAL_DB_NAME}: starting {self.get_id().name}...")
        self.executor_service = Executors.new_single_thread_executor()
        port = self.get_metrics_port()
        metrics_system = MetricsSystem(ServerArgument(port))
        metrics_web_ui = MetricsWebUI(metrics_system.metric_registry)
        metrics_web_ui.handlers.add(metrics_system.servlet_handlers)
        metrics_web_ui.initialize()
        self.server = metrics_web_ui.get_server(port)
        self.server.set_stop_timeout(10000)
        metrics_system.start()
        try:
            self.executor_service.execute(MetricsServiceThread(self.server))
            self.logger.info(f"{IoTDBConstant.GLOBAL_DB_NAME}: started {self.get_id().name} successfully, listening on ip {IoTDBDescriptor.get_instance().get_config().rpc_address} port {port}")
        except NullPointerException as e:
            # issue IOTDB-415
            self.stop_service()
            raise

    def restart_service(self):
        self.stop_service()
        self.start_service()

    def stop_service(self):
        if self.server is not None:
            try:
                self.server.stop()
                self.server = None
            except Exception as e:
                self.logger.error(f"Failed to close {self.get_id().name} because: {e}")
        if self.executor_service is not None:
            try:
                self.executor_service.shutdown()
                sleep(3)
                for t in Thread.enumerate():
                    if t.name == "MetricsServiceThread":
                        t.interrupt()
                break
            except Exception as e:
                self.logger.error(f"Failed to close {self.get_id().name} because: {e}")
        try:
            socket(AF_INET, SOCK_STREAM).connect(("localhost", self.get_metrics_port()))
        except ConnectionRefusedError:
            pass

    def check_and_wait_port_is_closed(self):
        while True:
            try:
                s = socket(AF_INET, SOCK_STREAM)
                s.connect(("localhost", self.get_metrics_port()))
                return
            except ConnectionRefusedError as e:
                break
        raise Exception(f"Port {self.get_metrics_port()} can not be closed.")

class MetricsServiceHolder:
    INSTANCE = MetricsService()

class ServiceType:
    METRICS_SERVICE = "metrics_service"

class IoTDBConstant:
    IOTDB_PACKAGE = "org.apache.iotdb"
    JMX_TYPE = "jmx_type"
    GLOBAL_DB_NAME = "global_db_name"

class StartupException(Exception):
    pass

class WrappedRunnable(Thread):
    def __init__(self, server):
        self.server = server
        super().__init__()

    def run(self):
        try:
            Thread.current_thread().name = "MetricsServiceThread"
            self.server.start()
            self.server.join()
        except Exception as e:
            logging.error(f"Failed to start {e}")

class MetricsSystem:
    pass

class ServerArgument:
    pass

class MetricsWebUI:
    def __init__(self, metric_registry):
        self.metric_registry = metric_registry
        super().__init__()

    @property
    def handlers(self):
        return []

    def initialize(self):
        pass

    def get_server(self, port):
        pass

class Server:
    def start(self):
        pass

    def set_stop_timeout(self, timeout):
        pass

    def stop(self):
        pass

    def join(self):
        pass
```

Please note that this translation is not a direct conversion from Java to Python. Some parts of the code may need further modifications or adjustments based on your specific requirements and constraints.