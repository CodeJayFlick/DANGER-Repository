Here is the translation of the Java code into Python:

```Python
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
from typing import Dict, Set, List

class CompactionTaskManager:
    _logger = logging.getLogger("COMPACTION")
    _instance = None
    _task_execution_pool: ThreadPoolExecutor = None
    _compaction_task_submission_threadpool: ThreadPoolExecutor = None
    _current_task_num = 0
    _min_max_priority_queue: deque = deque(maxlen=1000)
    _storage_group_tasks: Dict[str, set] = defaultdict(set)
    _compaction_task_futures: Dict[str, Dict[long, set]] = defaultdict(lambda: defaultdict(set))
    _task_submit_interval = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = CompactionTaskManager()
        return cls._instance

    def start(self):
        if self._task_execution_pool is None and IoTDBDescriptor.get_config().get_concurrent_compaction_thread() > 0:
            self._task_execution_pool = ThreadPoolExecutor(
                max_workers=IoTDBDescriptor.get_config().get_concurrent_compaction_thread(),
                thread_name_prefix="COMPACTION_ SERVICE"
            )
            self._compaction_task_submission_threadpool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="COMPACTION_SERVICE")
            self._task_submit_interval = IoTDBDescriptor.get_config().get_compaction_submission_interval()
            self._compaction_task_submission_threadpool.submit(self.submit_tasks_from_queue)
        self._logger.info("Compaction task manager started.")

    def stop(self):
        if self._task_execution_pool is not None:
            self._task_execution_pool.shutdown()
            self._compaction_task_submission_threadpool.shutdown()
            self._wait_for_termination()

    def wait_and_stop(self, milliseconds: int):
        if self._task_execution_pool is not None:
            self.await_termination(self._task_execution_pool, milliseconds)
            self.await_termination(self._compaction_task_submission_threadpool, milliseconds)
            self._logger.info("Waiting for task execution pool to shut down")
            self._wait_for_termination()
            self._storage_group_tasks.clear()

    def wait_all_compaction_finish(self):
        if self._task_execution_pool is not None:
            while self._task_execution_pool.active_count > 0 or len(self._min_max_priority_queue) > 0:
                try:
                    time.sleep(200)
                except InterruptedException as e:
                    self._logger.error("thread interrupted while waiting for compaction to end", e)
                    return
        self._storage_group_tasks.clear()
        self._logger.info("All compaction task finish")

    def wait_for_termination(self):
        start_time = int(time.time())
        while not self._task_execution_pool.is_shutdown():
            time.sleep(200)
            elapsed_time = int(time.time()) - start_time
            if elapsed_time % 60000 == 0:
                self._logger.info("CompactionManager has wait for {} seconds to stop", elapsed_time // 1000)
        self._task_execution_pool = None
        self._storage_group_tasks.clear()
        self._logger.info("CompactionManager stopped")

    def await_termination(self, service: ThreadPoolExecutor, milliseconds: int):
        try:
            service.shutdown()
            service.await_termination(milliseconds, time.time_unit().milliseconds)
        except InterruptedException as e:
            self._logger.warn("CompactionThreadPool can not be closed in {} ms", milliseconds)
            current_thread().interrupt()

    def add_task_to_waiting_queue(self, compaction_task: AbstractCompactionTask) -> bool:
        if not self._min_max_priority_queue.contains(compaction_task):
            self._logger.debug(
                "Add a compaction task {} to queue, current queue size is {}, current task num is {}", 
                compaction_task,
                len(self._min_max_priority_queue),
                self._current_task_num
            )
            self._min_max_priority_queue.add(compaction_task)
            return True

    def submit_tasks_from_queue(self):
        while self._current_task_num < IoTDBDescriptor.get_config().get_concurrent_compaction_thread() and len(self._min_max_priority_queue) > 0:
            task = self._min_max_priority_queue.pop()
            if task.check_valid_and_set_merging():
                self.submit_task(task.full_storage_group_name, task.time_partition, task)

    def submit_task(self, full_storage_group_name: str, time_partition: long, compaction_merge_task: Callable[[Void], Void]) -> None:
        if self._task_execution_pool is not None and not self._task_execution_pool.is_shutdown():
            future = self._task_execution_pool.submit(compaction_merge_task)
            CompactionScheduler.add_partition_compaction(full_storage_group_name, time_partition)
            self._compaction_task_futures[full_storage_group_name][time_partition].add(future)

    def abort_compaction(self, full_storage_group_name: str) -> None:
        sub_tasks = self._storage_group_tasks.get(full_storage_group_name, set())
        for future in list(sub_tasks):
            if not future.done() and not future.cancelled():
                future.cancel()
            sub_tasks.remove(future)

    def get_task_count(self) -> int:
        return self._task_execution_pool.active_count + len(self._min_max_priority_queue)

    def get_finish_task_num(self) -> long:
        return self._task_execution_pool.completed_task_count

    @classmethod
    def restart(cls):
        if IoTDBDescriptor.get_config().get_concurrent_compaction_thread() > 0:
            cls._instance = CompactionTaskManager()
            cls._compaction_task_submission_threadpool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="COMPACTION_SERVICE")
```

Please note that this is a direct translation of the Java code into Python.