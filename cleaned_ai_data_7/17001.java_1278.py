import logging

class FlushSubTaskPoolManager:
    _logger = logging.getLogger(__name__)

    def __init__(self):
        self.pool = IoTDBThreadPoolFactory.new_cached_thread_pool("flush_sub_task_service")

    @classmethod
    def get_instance(cls):
        return cls._instance_holder.instance

    @_logger.info("Flush sub task manager started.")
    def start(self):
        if not hasattr(self, "pool"):
            self.pool = IoTDBThreadPoolFactory.new_cached_thread_pool("flush_sub_task_service")
        self._logger.info("Flush sub task manager started.")

    @_logger.info("Flush sub task manager stopped")
    def stop(self):
        super().stop()
        self._logger.info("Flush sub task manager stopped")

class InstanceHolder:
    _instance = FlushSubTaskPoolManager()

InstanceHolder
