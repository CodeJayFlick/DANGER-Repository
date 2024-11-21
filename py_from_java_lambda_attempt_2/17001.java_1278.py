Here is the translation of the Java code to Python:
```
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
```
Note that I've used the `logging` module to implement logging, as there is no direct equivalent of Java's SLF4J in Python. Additionally, I've replaced the `ThreadName` class with a simple string literal for the thread pool name.

Also, please note that this translation assumes that you have implemented the following classes and functions:

* `IoTDBThreadPoolFactory`: A factory class to create a cached thread pool.
* `_logger.info()`: A logging function to log information messages.