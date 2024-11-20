Here is the equivalent Python code:

```Python
import threading
from queue import Queue
import unittest

class MessageQueue(Queue):
    pass

def task_generator(msg_queue: 'MessageQueue', num_jobs: int) -> None:
    for _ in range(num_jobs):
        msg_queue.put('Job')

class ServiceExecutor(threading.Thread):
    def __init__(self, msg_queue: 'MessageQueue'):
        threading.Thread.__init__(self)
        self.msg_queue = msg_queue

    def run(self) -> None:
        while True:
            job = self.msg_queue.get()
            if job is None:
                break
            print(f"Received Job {job}")

class TaskGenSrvExeTest(unittest.TestCase):
    @unittest.skip("Not implemented yet")
    def test_task_generator(self) -> None:
        msg_queue = MessageQueue()

        # Create a task generator thread with 1 job to submit.
        task_runnable = threading.Thread(target=task_generator, args=(msg_queue, 1))
        task_gen_thr = task_runnable
        task_gen_thr.start()
        
        self.assertIsNotNone(task_gen_thr)

        # Create a service executor thread.
        srv_runnable = ServiceExecutor(msg_queue)
        srv_exe_thr = srv_runnable
        srv_exe_thr.start()

        self.assertIsNotNone(srv_exe_thr)

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the built-in testing framework called `unittest`.