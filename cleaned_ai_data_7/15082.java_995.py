import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random

class Task:
    def __init__(self):
        self.id = str(random.randint(0, 100000))

    def get_id(self):
        return self.id

    def run(self):
        # This is where you would put your task's logic.
        pass

    def get_time_ms(self):
        return time.time() * 1000


class TaskTest:
    TASK_COUNT = 128 * 1024
    THREAD_COUNT = 8

    def __init__(self, factory, expected_execution_time):
        self.factory = factory
        self.expected_execution_time = expected_execution_time

    @staticmethod
    def get(future):
        try:
            return future.result()
        except (threading.ThreadError, Exception) as e:
            return None


def test_id_generation(factory, expected_execution_time):
    with ThreadPoolExecutor(max_workers=TaskTest.THREAD_COUNT) as service:
        tasks = [service.submit(lambda: factory().get_id()) for _ in range(TaskTest.TASK_COUNT)]

        ids = []
        for task in as_completed(tasks):
            result = Task.get(task.result())
            if result is not None and isinstance(result, str):
                ids.append(result)

    assert len(ids) == TaskTest.TASK_COUNT


def test_time_ms(factory, expected_execution_time):
    for i in range(10):
        time_taken = factory().get_time_ms()
        assert round(time_taken * (i + 1)) == round(expected_execution_time * (i + 1))


def test_to_string(factory, expected_execution_time):
    task = factory()
    assert task.get_id() is not None


# Example usage:
factory = lambda: Task()

test_id_generation(factory, 1000)
test_time_ms(factory, 1000)
test_to_string(factory, 1000)

