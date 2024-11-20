Here is the translation of the Java code to Python:
```python
import logging

class QueryTaskPoolManager:
    _logger = logging.getLogger(__name__)

    def __init__(self):
        config = IoTDBDescriptor.getInstance().getConfig()
        thread_cnt = config.get_concurrent_query_thread()
        self.pool = IoTDBThreadPoolFactory.new_fixed_pool(thread_cnt, "query_task")

    @classmethod
    def get_instance(cls):
        return cls._instance

    _instance = QueryTaskPoolManager()

    def get_logger(self):
        return self._logger

    def get_name(self):
        return "query task"

    def start(self):
        if not hasattr(self, 'pool'):
            config = IoTDBDescriptor.getInstance().getConfig()
            thread_cnt = config.get_concurrent_query_thread()
            self.pool = IoTDBThreadPoolFactory.new_fixed_pool(thread_cnt, "query_task")

    def stop(self):
        if hasattr(self, 'pool') and self.pool is not None:
            close()
            del self.pool

class InstanceHolder:
    _instance = QueryTaskPoolManager()

    def __init__(self):
        pass
```
Note that I've used the `logging` module to implement the equivalent of Java's `Logger`. Also, Python doesn't have a direct equivalent of Java's `@Override` annotation, so I've omitted it. Additionally, some methods in the original code are not implemented here (e.g., `close()`), as they were not provided with their implementation details.