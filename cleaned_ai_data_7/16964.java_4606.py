import logging
from concurrent.futures import ThreadPoolExecutor, ScheduledExecutorService, as_completed
from typing import Dict, List, Set

class MergeManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.mbean_name = f"org.apache.iotdb.db.engine.compaction.cross.inplace.manage.MergeManager"
        self.merge_write_rate_limiter = RateLimiter(0)

    @property
    def merge_write_rate_limiter(self) -> 'RateLimiter':
        throughout_mb_per_sec = IoTDBDescriptor.getInstance().getConfig().get_merge_write_throughput_mb_per_sec()
        if throughout_mb_per_sec == 0:
            self.merge_write_rate_limiter.set_rate(float('inf'))
        else:
            self.merge_write_rate_limiter.set_rate(throughout_mb_per_sec * 1024.0 * 1024.0)
        return self.merge_write_rate_limiter

    def submit_chunk_sub_task(self, task: 'MergeChunkHeapTask') -> Future['Void']:
        future = ThreadPoolExecutor().submit(task)
        storage_group_sub_tasks[task.get_storage_group_name()].add(future)
        return future

    def start(self):
        JMXService.register_mbean(self, self.mbean_name)

        if not hasattr(self, 'merge_chunk_sub_task_pool'):
            chunk_sub_thread_num = IoTDBDescriptor.getInstance().getConfig().get_merge_chunk_sub_thread_num()
            if chunk_sub_thread_num <= 0:
                chunk_sub_thread_num = 1
            self.merge_chunk_sub_task_pool = ThreadPoolExecutor(chunk_sub_thread_num)
            task_cleaner_thread_pool = ScheduledExecutorService()
            task_cleaner_thread_pool.schedule_at_fixed_rate(self.clean_finished_task, 30, 30)

        self.logger.info("MergeManager started")

    def stop(self):
        if hasattr(self, 'task_cleaner_thread_pool'):
            try:
                self.task_cleaner_thread_pool.shutdown()
            except Exception as e:
                self.logger.error(f"Task cleaner thread pool can not be closed: {e}")
            task_cleaner_thread_pool = None

        if hasattr(self, 'merge_chunk_sub_task_pool'):
            try:
                self.merge_chunk_sub_task_pool.shutdown()
            except Exception as e:
                self.logger.error(f"Merge chunk sub-task pool can not be closed: {e}")
            self.merge_chunk_sub_task_pool = None
            storage_group_main_tasks.clear()
            storage_group_sub_tasks.clear()

        self.logger.info("MergeManager stopped")

    def await_termination(self, service: 'ExecutorService', milliseconds):
        try:
            service.shutdown()
            service.await_termination(milliseconds)
        except Exception as e:
            self.logger.warn(f"Task pool can not be closed in {milliseconds} ms: {e}")
        finally:
            if hasattr(service, "shutdown_now"):
                service.shutdown_now()

    def abort_merge(self, storage_group):
        sub_tasks = storage_group_sub_tasks.get(storage_group, set())
        for task in list(sub_tasks):
            try:
                future.cancel()
            except Exception as e:
                self.logger.error(f"Task {task} can not be cancelled: {e}")
            finally:
                sub_tasks.remove(task)

    def clean_finished_task(self):
        for storage_group_sub_tasks in storage_group_sub_tasks.values():
            storage_group_sub_tasks[:] = [task for task in storage_group_sub_tasks if not (task.done() or task.cancelled())]

    @property
    def id(self) -> 'ServiceType':
        return ServiceType.MERGE_SERVICE

    def collect_task_status(self):
        result = [[], []]
        for storage_group, tasks in storage_group_main_tasks.items():
            for task in tasks:
                if not (task.done() or task.cancelled()):
                    result[0].append(task)
                else:
                    break
            for task in list(tasks[:]):
                try:
                    future.cancel()
                except Exception as e:
                    self.logger.error(f"Task {task} can not be cancelled: {e}")
                finally:
                    tasks[:] = [t for t in tasks if not (t.done() or t.cancelled())]

        for storage_group, tasks in storage_group_sub_tasks.items():
            for task in tasks:
                if not (task.done() or task.cancelled()):
                    result[1].append(task)
                else:
                    break
            for task in list(tasks[:]):
                try:
                    future.cancel()
                except Exception as e:
                    self.logger.error(f"Task {task} can not be cancelled: {e}")
                finally:
                    tasks[:] = [t for t in tasks if not (t.done() or t.cancelled())]

        return result

    def gen_merge_task_report(self):
        status_maps = self.collect_task_status()
        builder = f"Main tasks:\n"
        for storage_group, task_list in status_maps[0]:
            builder += f"\t{storage_group}\n"
            for task in task_list:
                if not (task.done() or task.cancelled()):
                    builder += f"\t\tTask {task} is running\n"
                else:
                    break
        builder += "Sub tasks:\n"
        for storage_group, task_list in status_maps[1]:
            builder += f"\t{storage_group}\n"
            for task in task_list:
                if not (task.done() or task.cancelled()):
                    builder += f"\t\tTask {task} is running\n"
                else:
                    break
        return builder

    def print_merge_status(self):
        self.logger.info(f"Running tasks:\n{self.gen_merge_task_report()}")

class TaskStatus:
    def __init__(self, task: 'MergeFuture'):
        self.task_name = task.get_task_name()
        self.created_time = task.get_created_time()
        self.progress = task.get_progress()
        self.is_done = task.done()
        self.is_cancelled = task.cancelled()

    @property
    def is_done(self):
        return self._is_done

    @property
    def is_cancelled(self):
        return self._is_cancelled

    def __str__(self) -> str:
        return f"{self.task_name}, {self.created_time}, {self.progress}, done: {self.is_done}, cancelled: {self.is_cancelled}"

class RateLimiter:
    def __init__(self, rate):
        self.rate = rate
