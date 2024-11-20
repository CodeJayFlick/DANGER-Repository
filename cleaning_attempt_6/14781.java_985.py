import logging
from queue import Queue
import threading
import time

class TaskGenerator(threading.Thread):
    def __init__(self, msg_queue: Queue, msg_count: int):
        self.msg_queue = msg_queue
        self.msg_count = msg_count
        super().__init__()

    def submit(self, msg: str) -> None:
        try:
            self.msg_queue.put(msg)
        except Exception as e:
            logging.error(e)

    def run(self) -> None:
        count = self.msg_count

        while count > 0:
            status_msg = f"Message-{count} submitted by {threading.current_thread().name}"
            self.submit(status_msg)
            logging.info(status_msg)
            count -= 1
            time.sleep(1)

if __name__ == "__main__":
    # Example usage
    msg_queue = Queue()
    task_generator = TaskGenerator(msg_queue, 10)  # submit 10 messages
    task_generator.start()

    while True:
        pass  # wait for the thread to finish
