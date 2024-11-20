import logging
from queue import Queue
import threading
import time

class ArithmeticSumTask:
    def __init__(self, number_of_elements):
        self.number_of_elements = number_of_elements

    def call(self):
        return ap(self.number_of_elements)

    def on_pre_call(self):
        if self.number_of_elements < 0:
            raise ValueError("n is less than 0")

    def on_post_call(self, result):
        logging.info(str(result))

    def on_error(self, throwable):
        raise Exception("Should not occur")


def ap(i):
    try:
        time.sleep(i)
    except:
        logging.error("Exception caught.")
    return i * (i + 1) // 2


class AsynchronousService:
    def __init__(self, queue):
        self.queue = queue

    def execute(self, task):
        thread = threading.Thread(target=task.call)
        thread.start()

    def close(self):
        pass


def main():
    logging.basicConfig(level=logging.INFO)

    service = AsynchronousService(Queue())

    tasks = [ArithmeticSumTask(1000), ArithmeticSumTask(500), ArithmeticSumTask(2000), ArithmeticSumTask(1)]

    for task in tasks:
        service.execute(task)


if __name__ == "__main__":
    main()
