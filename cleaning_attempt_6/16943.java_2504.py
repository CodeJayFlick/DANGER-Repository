import logging
from concurrent.futures import ThreadPoolExecutor, LinkedBlockingQueue
from time import sleep

class ContinuousQueryTaskPoolManager:
    _logger = None
    _pool = None
    _n_threads = 0

    def __init__(self):
        self._logger = logging.getLogger(__name__)
        config = IoTDBDescriptor.getInstance().getConfig()
        self._n_threads = config.getContinuousQueryThreadNum()
        self._logger.info("Initializing ContinuousQueryTaskPoolManager with {} threads".format(self._n_threads))
        self._pool = ThreadPoolExecutor(max_workers=self._n_threads, queue=LinkedBlockingQueue(maxsize=config.getMaxPendingContinuousQueryTasks()), thread_name_prefix='continuous_query_service')

    def submit(self, task):
        try:
            super().submit(task)
        except Exception as e:
            task.on_rejection()

    @property
    def logger(self):
        return self._logger

    @property
    def name(self):
        return "Continuous Query Task"

    def start(self):
        if not self._pool:
            self._pool = ThreadPoolExecutor(max_workers=self._n_threads, queue=LinkedBlockingQueue(maxsize=IoTDBDescriptor.getInstance().getConfig().getMaxPendingContinuousQueryTasks()), thread_name_prefix='continuous_query_service')

    @classmethod
    def get_instance(cls):
        return cls.InstanceHolder.INSTANCE

    class InstanceHolder:
        _instance = None

        def __init__(self):
            pass

        INSTANCE = InstanceHolder()
