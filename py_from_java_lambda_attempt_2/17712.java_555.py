Here is a translation of the Java code into equivalent Python:

```Python
import logging
from concurrent.futures import ThreadPoolExecutor, LinkedBlockingQueue
from typing import Any

class WindowEvaluationTaskPoolManager:
    _logger = None
    _pool = None

    def __init__(self):
        config = IoTDBDescriptor.getInstance().getConfig()
        n_threads = config.getConcurrentWindowEvaluationThread()
        self._logger.info(f"Initializing with {n_threads} threads")
        self._pool = ThreadPoolExecutor(
            max_workers=n_threads,
            queue=LinkedBlockingQueue(maxsize=config.getMaxPendingWindowEvaluationTasks()),
            thread_name_prefix="window_evaluation_service"
        )

    def submit(self, task: Any) -> None:
        try:
            super().submit(task)
        except Exception as e:
            task.on_rejection()

    @property
    def logger(self):
        return self._logger

    @property
    def name(self):
        return "window evaluation task"

    def start(self):
        if not self._pool:
            config = IoTDBDescriptor.getInstance().getConfig()
            n_threads = config.getConcurrentWindowEvaluationThread()
            thread_name_prefix = "window_evaluation_service"
            self._pool = IoTDBThreadPoolFactory.new_fixed_thread_pool(n_threads, thread_name_prefix)

    @classmethod
    def get_instance(cls):
        return cls.InstanceHolder.INSTANCE

class InstanceHolder:
    _instance = None

    def __init__(self):
        pass

    @property
    def INSTANCE(self):
        if not self._instance:
            self._instance = WindowEvaluationTaskPoolManager()
        return self._instance


# Define IoTDBDescriptor and IoTDBThreadPoolFactory classes as needed in your Python code.
```

Please note that the `IoTDBDescriptor` and `IoTDBThreadPoolFactory` are Java-specific classes, which do not have direct equivalents in Python. You would need to implement these classes or use alternative libraries that provide similar functionality.

Also, this translation assumes a basic understanding of Python syntax and does not include any error handling for missing imports or undefined variables.