Here is the translation of the Java code to Python:
```
import queue
from typing import List

class QueueDatabase:
    def __init__(self, *exceptions: Exception):
        self.data = queue.Queue()
        self.exceptions_list: List[Exception] = [exc for exc in exceptions]

    def add(self, task: 'QueueTask') -> 'QueueTask':
        self.data.put(task)
        return task

    def peek(self) -> 'QueueTask':
        try:
            return self.data.get_nowait()
        except queue.Empty:
            raise IsEmptyException()

    def dequeue(self) -> 'QueueTask':
        try:
            return self.data.get_nowait()
        except queue.Empty:
            raise IsEmptyException()

    def get(self, task_id: str) -> None:
        pass

class QueueTask:
    # add any necessary attributes and methods here
    pass

class IsEmptyException(Exception):
    pass
```
Note that I've used the `queue` module from Python's standard library to implement a queue data structure. The rest of the code is similar in spirit to the Java original, but with some minor differences due to the nature of Python (e.g., using lists instead of arrays).