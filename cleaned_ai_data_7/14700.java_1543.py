import concurrent.futures

class SimpleMessageQueue:
    def __init__(self, bound):
        self.queue = concurrent.futures.ThreadPoolExecutor(max_workers=bound).queue()

    def put(self, msg):
        try:
            self.queue.put(msg)
        except Exception as e:
            raise InterruptedError from e

    def take(self):
        try:
            return self.queue.get()
        except Exception as e:
            raise InterruptedError from e
