Here is the translation of the given Java code into equivalent Python:

```Python
import threading
from queue import Queue
from typing import Any, List, Tuple

class IncrementalLoadJob:
    def __init__(self, threaded_model: 'ThreadedTableModel', listener: 'IncrementalJobListener'):
        self.threaded_model = threaded_model
        self.listener = listener
        self.update_manager = threaded_model.get_update_manager()

    def run(self) -> None:
        incremental_accumulator = IncrementalUpdatingAccumulator()
        notify_started()
        
        try:
            do_execute(incremental_accumulator)
        except Exception as e:
            if not has_cause(e, InterruptedException):
                name = self.threaded_model.name
                print(f"Unexpected exception loading table model '{name}'")
                
        interrupted = threading.current_thread().is_interruped()
        notify_completed(interrupted)

    def do_execute(self, incremental_accumulator: 'IncrementalUpdatingAccumulator') -> None:
        try:
            self.threaded_model.do_load(incremental_accumulator)
            if not self.update_manager.is_cancelled():
                flush(incremental_accumulator)
        except CancelledException as e:
            pass
        
    def notify_started(self) -> None:
        if self.listener is not None:
            SystemUtilities.run_if_swing_or_post_swing_later(lambda: self.listener.loading_started())

    def notify_completed(self, was_cancelled: bool) -> None:
        if self.listener is not None:
            SystemUtilities.run_if_swing_or_post_swing_later(lambda: self.listener.loading_finished(was_cancelled))
        
        update_manager.remove_threaded_table_listener(self)

    def cancel(self) -> None:
        self.update_manager.get_task_monitor().cancel()
        incremental_accumulator.cancel()

    def load_pending(self) -> None:
        pass

    def loading_started(self) -> None:
        pass

    def loading_finished(self, was_cancelled: bool) -> None:
        completed_callback_latch.count_down()


class IncrementalUpdatingAccumulator(Queue):
    def __init__(self):
        super().__init__()
        
    def add(self, t: Any) -> None:
        self.put(t)
    
    def cancel(self) -> None:
        pass

    def flush_data(self) -> None:
        pass


def notify_started() -> None:
    # code here
    pass


def notify_completed(was_cancelled: bool) -> None:
    # code here
    pass


class ThreadedTableModel:
    def __init__(self):
        self.name = ''
        
    def get_update_manager(self) -> 'ThreadedTableUpdateManager':
        return None
    
    def do_load(self, incremental_accumulator: 'IncrementalUpdatingAccumulator') -> None:
        # code here
        pass


class ThreadedTableUpdateManager:
    def __init__(self):
        self.task_monitor = TaskMonitor()
        
    def get_task_monitor(self) -> 'TaskMonitor':
        return self.task_monitor
    
    def remove_threaded_table_listener(self, listener: Any) -> None:
        # code here
        pass


class IncrementalJobListener:
    def loading_started(self) -> None:
        # code here
        pass

    def loading_finished(self, was_cancelled: bool) -> None:
        # code here
        pass
```

Please note that Python does not have direct equivalent of Java's CountDownLatch. You can use threading.Condition or Event to achieve similar functionality.