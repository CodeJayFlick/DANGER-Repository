import logging

class GuardedQueue:
    def __init__(self):
        self.source_list = []

    @property
    def logger(self):
        return logging.getLogger(__name__)

    def get(self) -> int | None:
        while not self.source_list:
            self.logger.info("waiting")
            import time
            time.sleep(0.1)
        self.logger.info("getting")
        return self.source_list[-1]

    def put(self, e: int):
        self.logger.info("putting")
        self.source_list.append(e)
        self.logger.info("notifying")

if __name__ == "__main__":
    queue = GuardedQueue()
    # test the queue
    for i in range(5):
        queue.put(i)
        print(f"Put {i}")
    while True:
        item = queue.get()
        if item is None:
            break
        print(f"Got {item}")

