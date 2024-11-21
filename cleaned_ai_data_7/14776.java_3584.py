import logging
import threading
import time
from queue import Queue

logging.basicConfig(level=logging.INFO)

class MessageQueue(Queue):
    pass

class TaskGenerator(threading.Thread):
    def __init__(self, msg_queue, num_jobs):
        super().__init__()
        self.msg_queue = msg_queue
        self.num_jobs = num_jobs

    def run(self):
        for _ in range(self.num_jobs):
            # submit a job to the message queue here
            pass

class ServiceExecutor(threading.Thread):
    def __init__(self, msg_queue):
        super().__init__()
        self.msg_queue = msg_queue

    def run(self):
        while True:
            try:
                # retrieve and process a job from the message queue here
                break  # exit loop when no more jobs available
            except Exception as e:
                logging.error(str(e))

def main():
    SHUTDOWN_TIME = 15

    msg_queue = MessageQueue()

    logging.info("Submitting TaskGenerators and ServiceExecutor threads.")

    task_runnables = [
        TaskGenerator(msg_queue, 5),
        TaskGenerator(msg_queue, 1),
        TaskGenerator(msg_queue, 2)
    ]

    srv_runnable = ServiceExecutor(msg_queue)

    executor_threads = []

    for runnable in [task_runnables[0], task_runnables[1], task_runnables[2]]:
        t = threading.Thread(target=runnable.run)
        t.start()
        executor_threads.append(t)

    srv_t = threading.Thread(target=srv_runnable.run)
    srv_t.start()
    executor_threads.append(srv_t)

    logging.info("Initiating shutdown.")
    for t in executor_threads:
        t.join()

    if not all([t.is_alive() for t in executor_threads]):
        logging.info("Executor was shut down and Exiting.")
        time.sleep(SHUTDOWN_TIME)
    else:
        logging.info("All threads completed. Shutting down.")

if __name__ == "__main__":
    main()
