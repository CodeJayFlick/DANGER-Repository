import logging
from queue import Queue

class ServiceExecutor:
    def __init__(self, msg_queue: Queue):
        self.msg_queue = msg_queue

    def run(self):
        while not Thread.current_thread().is_alive():
            try:
                message = self.msg_queue.get_nowait()
                if message is not None:
                    logging.info(f"{message} is served.")
                else:
                    logging.info("Service Executor: Waiting for Messages to serve...")
                time.sleep(1)
            except Exception as e:
                logging.error(e)

import threading
import time

class MessageQueue(Queue):
    pass

if __name__ == "__main__":
    msg_queue = MessageQueue()
    service_executor = ServiceExecutor(msg_queue)
    thread = threading.Thread(target=service_executor.run())
    thread.start()

# Note: The above code is not a direct translation, but rather an equivalent implementation in Python.
