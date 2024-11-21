import threading
from queue import PriorityQueue

class Message:
    def __init__(self, message, priority):
        self.message = message
        self.priority = priority


class QueueManager:
    def __init__(self, capacity):
        self.queue = PriorityQueue()
        self.capacity = capacity

    def publishMessage(self, message):
        if not self.is_queue_full():
            self.queue.put(message)
        else:
            print("Queue is full. Cannot add more messages.")

    def is_queue_full(self):
        return self.queue.qsize() >= self.capacity


class Worker(threading.Thread):
    def __init__(self, queue_manager):
        threading.Thread.__init__(self)
        self.queue_manager = queue_manager

    def run(self):
        while True:
            try:
                message = self.queue_manager.queue.get()
                print(f"Processing {message.message} with priority {message.priority}")
            except Exception as e:
                print("Error processing messages: ", str(e))
            finally:
                self.queue_manager.queue.task_done()


if __name__ == "__main__":
    queue_manager = QueueManager(10)

    # push some message to queue
    for i in range(10):
        queue_manager.publishMessage(Message(f"Low Message Priority {i}", 0))

    for i in range(10):
        queue_manager.publishMessage(Message(f"High Message Priority {i}", 1))

    worker = Worker(queue_manager)
    worker.start()
