import logging
from concurrent.futures import deque
from typing import Any

class FlushManager:
    def __init__(self):
        self.config = IoTDBConfig()
        self.ts_file_processor_queue = deque()
        self.flush_pool = FlushTaskPoolManager()

    @property
    def logger(self) -> Logger:
        return logging.getLogger(FlushManager.__name__)

    def start(self) -> None:
        try:
            JMXService.register_mbean(self, ServiceType.FLUSH_SERVICE)
        except Exception as e:
            raise StartupException(f"Failed to register MBean: {e}")

        self.flush_pool.start()
        FlushSubTaskPoolManager().start()

    def stop(self) -> None:
        self.flush_pool.stop()
        FlushSubTaskPoolManager().stop()
        JMXService.deregister_mbean(ServiceType.FLUSH_SERVICE)

    @property
    def id(self) -> ServiceType:
        return ServiceType.FLUSH_SERVICE

    @property
    def number_of_working_tasks(self) -> int:
        return self.flush_pool.working_tasks_number()

    @property
    def number_of_pending_tasks(self) -> int:
        return self.flush_pool.waiting_tasks_number()

    @property
    def number_of_working_subtasks(self) -> int:
        return FlushSubTaskPoolManager().working_tasks_number()

    @property
    def number_of_pending_subtasks(self) -> int:
        return FlushSubTaskPoolManager().waiting_tasks_number()

class TsFileProcessor:
    pass

class FlushThread(WrappedRunnable):
    def run_may_throw(self) -> None:
        ts_file_processor = self.ts_file_processor_queue.pop()
        if ts_file_processor is not None:
            ts_file_processor.flush_one_mem_table()
            ts_file_processor.set_managed_by_flush_manager(False)
            if self.logger.is_enabled(logging.DEBUG):
                self.logger.debug(f"Flush Thread re-register TSProcessor {ts_file_processor.get_ts_file_resource().get_ts_file().get_absolute_path()} to the queue.")
            self.register_ts_file_processor(ts_file_processor)

    def register_ts_file_processor(self, ts_file_processor: TsFileProcessor) -> None:
        if not ts_file_processor.is_managed_by_flush_manager():
            self.ts_file_processor_queue.appendleft(ts_file_processor)
            if self.logger.is_enabled(logging.DEBUG):
                self.logger.debug(f"{} begin to submit a flush thread, flushing memtable size: {}, queue size: {}".format(
                    ts_file_processor.get_ts_file_resource().get_ts_file().get_absolute_path(),
                    ts_file_processor.get_flushing_mem_table_size(),
                    len(self.ts_file_processor_queue)
                ))
            ts_file_processor.set_managed_by_flush_manager(True)
            self.flush_pool.submit(FlushThread())

    def __str__(self) -> str:
        return f"TSProcessors in the queue: {len(self.ts_file_processor_queue)}, TaskPool size {self.flush_pool.working_tasks_number()} + {self.flush_pool.waiting_tasks_number()},"

class FlushManagerMBean(IService):
    pass

FlushManager.instance = FlushManager()
