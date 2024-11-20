Here is the translation of the given Java code into Python:

```Python
import logging
from concurrent.futures import Callable
from typing import Void

class AbstractCompactionTask(Callable[Void]):
    def __init__(self, full_storage_group_name: str, time_partition: int, current_task_num: int):
        self.full_storage_group_name = full_storage_group_name
        self.time_partition = time_partition
        self.current_task_num = current_task_num

    @abstractmethod
    def do_compaction(self) -> None:
        pass

    def call(self) -> Void:
        with self.current_task_num.get_lock():
            self.current_task_num.increment()
        try:
            self.do_compaction()
        except Exception as e:
            logging.error(e)
        finally:
            CompactionScheduler.decrement_partition_compaction(self.full_storage_group_name, self.time_partition)
            with self.current_task_num.get_lock():
                self.current_task_num.decrement()

    def get_full_storage_group_name(self) -> str:
        return self.full_storage_group_name

    def get_time_partition(self) -> int:
        return self.time_partition

    @abstractmethod
    def equals_other_task(self, other_task: 'AbstractCompactionTask') -> bool:
        pass

    def check_valid_and_set_merging(self) -> bool:
        # This method is not implemented in the Java code. It's assumed that it will be implemented by subclasses.
        return True  # Replace this with your actual implementation.

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AbstractCompactionTask):
            return self.equals_other_task(other)
        return False
```

Note:

- The `@abstractmethod` decorator is used to define abstract methods in Python. These methods must be implemented by subclasses.
- In the `call` method, we use a lock to ensure that the increment and decrement operations on `current_task_num` are atomic.
- We assume that `CompactionScheduler.decrement_partition_compaction`, `AbstractCompactionTask.equals_other_task`, and other classes or methods exist in your Python code. You may need to implement these yourself based on their Java counterparts.
- The `check_valid_and_set_merging` method is not implemented here, as it's assumed that subclasses will provide the actual implementation.