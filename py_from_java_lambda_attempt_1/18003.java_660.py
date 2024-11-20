Here is the translation of the Java code into Python:

```Python
import os
import logging
from thrift import TTransportException
from thrift.transport.TSocketWrapper import TSocketWrapper
from thrift.protocol.TProtocol import TProtocol
from thrift.server.TServer import TServer
from thrift.server.TProcessor import TProcessor

class EnvironmentUtils:
    logger = logging.getLogger(__name__)

    config = IoTDBConfig()
    directory_manager = DirectoryManager()

    TEST_QUERY_JOB_ID = 1
    test_query_context = QueryContext(TEST_QUERY_JOB_ID)

    old_seq_ts_file_size = config.get_seq_ts_file_size()
    old_unseq_ts_file_size = config.get_unseq_ts_file_size()
    old_group_size_in_byte = config.get_memtable_size_threshold()

    daemon = None

    t_configuration = TConfigurationConst.default_t_configuration
    examine_ports = Boolean.parse_boolean(os.environ.get("test.port.closed", "false"))

    @classmethod
    def clean_env(cls):
        # wait all compaction finished
        CompactionTaskManager().wait_all_compaction_finish()
        
        try:
            UDFRegistrationService().deregister_all()
            TriggerRegistrationService().deregister_all()
            ContinuousQueryService().deregister_all()
        except (UDFRegistrationException, TriggerManagementException, ContinuousQueryException) as e:
            cls.logger.error(f"Failed to deregister all: {e}")
        
        if cls.daemon is not None:
            cls.daemon.stop()
            cls.daemon = None
        
        QueryResourceManager().end_query(TEST_QUERY_JOB_ID)
        
        # clear opened file streams
        FileReaderManager().close_and_remove_all_opened_readers()

        if cls.examine_ports:
            closed = cls._examine_ports()
            if not closed:
                try:
                    time.sleep(10)
                except InterruptedException as e:
                    pass
                
                if not cls._examine_ports():
                    raise Exception("Failed to close some ports")
        
        # clean storage group manager
        StorageEngine().delete_all()

    @classmethod
    def _examine_ports(cls):
        transport = TSocketWrapper(t_configuration, "127.0.0.1", 6667, 100)
        if not transport.is_open():
            try:
                transport.open()
                cls.logger.error("Stop daemon failed. 6667 can be connected now.")
                transport.close()
                return False
            except TTransportException as e:
                pass
        
        # try sync service
        transport = TSocketWrapper(t_configuration, "127.0.0.1", 5555, 100)
        if not transport.is_open():
            try:
                transport.open()
                cls.logger.error("Stop Sync daemon failed. 5555 can be connected now.")
                transport.close()
                return False
            except TTransportException as e:
                pass
        
        # try jmx connection
        try:
            url = JMXServiceURL("service:jmx:rmi:///jndi/rmi://localhost:31999/jmxrmi")
            connector = JMXConnectorFactory.connect(url)
            cls.logger.error("Stop JMX failed. 31999 can be connected now.")
            connector.close()
            return False
        except IOException as e:
            pass
        
        # try MetricService
        try:
            socket = Socket()
            socket.connect(InetSocketAddress("127.0.0.1", 8181), 100)
            cls.logger.error("Stop MetricService failed. 8181 can be connected now.")
            return False
        except Exception as e:
            pass
        
        # do nothing
        return True

    @classmethod
    def clean_all_dir(cls):
        for path in directory_manager.get_all_sequence_file_folders():
            cls._clean_dir(path)
        
        for path in directory_manager.get_all_unsequence_file_folders():
            cls._clean_dir(path)

        cls._clean_dir(config.get_system_dir())
        cls._clean_dir(config.get_wal_dir())
        cls._clean_dir(config.get_query_dir())
        cls._clean_dir(config.get_tracing_dir())
        cls._clean_dir(config.get_udf_dir())
        cls._clean_dir(config.get_trigger_dir())

    @classmethod
    def _clean_dir(cls, dir):
        try:
            os.rmdir(dir)
        except OSError as e:
            pass

    @classmethod
    def close_stat_monitor(cls):
        config.set_enable_stat_monitor(False)

    @classmethod
    def env_set_up(cls):
        cls.logger.warn("EnvironmentUtil setup...")
        
        IoTDBDescriptor().get_instance().set_config(config, True)
        # we do not start 8181 port in test.
        config.set_enable_metric_service(False)
        config.set_avg_series_point_number_threshold(int.max_value)

        if cls.daemon is None:
            cls.daemon = IoTDB()

        try:
            EnvironmentUtils.daemon.active()
        except Exception as e:
            raise Exception(f"Failed to start daemon: {e}")

    @classmethod
    def stop_daemon(cls):
        if cls.daemon is not None:
            cls.daemon.stop()

    @classmethod
    def shutdown_daemon(cls):
        try:
            EnvironmentUtils.daemon.shutdown()
        except Exception as e:
            raise Exception(f"Failed to shut down daemon: {e}")

    @classmethod
    def active_daemon(cls):
        if cls.daemon is not None:
            cls.daemon.active()

    @classmethod
    def reactive_daemon(cls):
        if cls.daemon is None:
            cls.daemon = IoTDB()
            EnvironmentUtils.daemon.active()
        else:
            EnvironmentUtils.active_daemon()

    @classmethod
    def restart_daemon(cls):
        try:
            EnvironmentUtils.shutdown_daemon()
        except Exception as e:
            raise Exception(f"Failed to shut down daemon: {e}")
        
        cls.stop_daemon()
        IoTDB().meta_manager.clear()
        TsFileResourceManager().clear()
        EnvironmentUtils.reactive_daemon()

    @classmethod
    def create_all_dir(cls):
        for path in directory_manager.get_all_sequence_file_folders():
            cls._create_dir(path)
        
        for path in directory_manager.get_all_unsequence_file_folders():
            cls._create_dir(path)

        cls._create_dir(config.get_system_dir())
        sg_dir = os.path.join(FilePathUtils.regularize_path(config.get_system_dir()), "storage_groups")
        cls._create_dir(sg_dir)
        cls._create_dir(config.get_wal_dir())
        cls._create_dir(config.get_query_dir())
        cls._create_dir(TestConstant.OUTPUT_DATA_DIR)

    @classmethod
    def _create_dir(cls, dir):
        try:
            os.makedirs(dir, exist_ok=True)
        except OSError as e:
            pass

if __name__ == "__main__":
    EnvironmentUtils()
```

Please note that Python does not have direct equivalent of Java's `try-with-resources` statement. However, you can use a context manager to achieve similar functionality.

Also, the code assumes that some classes and methods are defined elsewhere in your project (e.g., `IoTDBConfig`, `DirectoryManager`, etc.). You will need to define these yourself or import them from another module.