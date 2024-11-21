import logging
from threading import Thread
import time
import random

class IoTDB:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.mbean_name = f"IoTDB:{IoTConstant.IOTDB_PACKAGE}:{IoTConstant.JMX_TYPE}"
        self.register_manager = RegisterManager()
        self.meta_manager = MManager.getInstance()

    @classmethod
    def get_instance(cls):
        return cls._instance

    _instance = None

    @staticmethod
    def set_meta_manager(meta_manager):
        IoTDB._instance.meta_manager = meta_manager

    @staticmethod
    def set_cluster_mode():
        IoTDB._instance.cluster_mode = True

    @staticmethod
    def is_cluster_mode():
        return IoTDB._instance.cluster_mode

    def active(self):
        startup_checks = StartupChecks()
        try:
            startup_checks.verify()
        except Exception as e:
            self.logger.error(f"Failed to start because some checks failed: {e}")
            return

        try:
            self.set_up()
        except Exception as e:
            self.deactivate()
            self.logger.error("Meet error while starting up.")
            return

        self.logger.info("IoTDB has started.")

    def set_up(self):
        self.logger.info("Setting up IoTDB...")
        runtime = Runtime()
        shutdown_hook = Thread(target=self.shutdown)
        runtime.add_shutdown_hook(shutdown_hook)

        self.set_uncaught_exception_handler()

        self.init_m_manager()

        self.register_manager.register(JMXService.getInstance())
        # ... register other services ...

    def init_m_manager(self):
        start_time = time.time()
        self.meta_manager.init()
        end_time = time.time() - start_time
        self.logger.info(f"Spent {end_time} seconds to recover schema.")

    def deactivate(self):
        self.logger.info("Deactivating IoTDB...")
        self.register_manager.deregister_all()

    @staticmethod
    def shutdown():
        try:
            IoTDB.get_instance().deactivate()
        except Exception as e:
            logging.error(f"Meet error while shutting down: {e}")

if __name__ == "__main__":
    iotdb = IoTDB()
    iotdb.active()
