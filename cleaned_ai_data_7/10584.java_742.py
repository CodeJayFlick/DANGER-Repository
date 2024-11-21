import threading
from queue import Queue, Empty
from typing import Any, List

class Job:
    def __init__(self):
        self._task_monitor = None
        self._cancelled = False
        self._completed = False

    @property
    def task_monitor(self) -> Any:
        return self._task_monitor

    @task_monitor.setter
    def task_monitor(self, monitor: Any):
        self._task_monitor = monitor

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    @is_cancelled.setter
    def is_cancelled(self, cancelled: bool):
        self._cancelled = cancelled

    @property
    def completed(self) -> bool:
        return self._completed

    @completed.setter
    def completed(self, completed: bool):
        self._completed = completed

    def run(self, monitor: Any):
        pass  # to be implemented by subclasses

class AbstractWorker:
    def __init__(self,
                 queue: Queue,
                 is_persistent_thread: bool,
                 name: str,
                 share_thread_pool: bool,
                 task_monitor: Any) -> None:

        self._concurrent_q = ConcurrentQ(queue)
        self._busy_listener = None
        self._is_disposed = False

    def set_task_monitor(self, monitor: Any):
        self._concurrent_q.set_monitor(monitor)

    class ProgressListener:
        def task_started(self, id: int, item: Job) -> None:
            pass  # to be implemented by subclasses

        def task_ended(self, id: int, item: Job, total_count: int, completed_count: int) -> None:
            if self._concurrent_q.is_empty():
                set_busy(False)

        def progress_changed(self, id: int, item: Job, current_progress: int) -> None:
            pass  # to be implemented by subclasses

    class JobCallback:
        def process(self, job: Job, monitor: Any):
            if job.is_cancelled:
                return
            try:
                job.run(monitor)
            except CancelledException as e:
                report_exception(e, job)

    @staticmethod
    def report_exception(t: Exception, job: Job) -> None:
        pass  # to be implemented by subclasses

class ConcurrentQ(Queue):
    def __init__(self, queue: Queue):
        self._queue = queue
        self._monitor = None

    def add(self, item: Any) -> None:
        if not isinstance(item, Job):
            raise ValueError("Item must be an instance of Job")

        try:
            self.put_nowait(item)
        except Empty as e:
            pass  # to be implemented by subclasses

    def cancel_all_tasks(self, interrupt_running_job: bool = False) -> List[Job]:
        return [self.get() for _ in range(len(self))]

class BusyListener:
    @property
    def is_busy(self):
        raise NotImplementedError("is_busy must be implemented")

def set_busy(b: bool) -> None:
    pass  # to be implemented by subclasses

# Example usage:

if __name__ == "__main__":
    queue = Queue()
    worker = AbstractWorker(queue, True, "worker", False, None)
    job1 = Job()  # create a new instance of the Job class
    job2 = Job()

    worker.set_task_monitor(None)

    try:
        while not worker.is_disposed():
            if not worker._concurrent_q.isEmpty():
                item = worker._concurrent_q.get()
                print(f"Processing {item}")
            else:
                break

    except CancelledException as e:
        report_exception(e, job1)
