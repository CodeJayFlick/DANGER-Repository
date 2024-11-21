Here is the translation of the Java code to Python:

```Python
import threading
import queue
import time
import logging

logging.basicConfig(level=logging.INFO)

class ItemQueue:
    def __init__(self):
        self.queue = queue.Queue()

    def put(self, item):
        self.queue.put(item)

    def get(self):
        return self.queue.get()


class Producer(threading.Thread):
    def __init__(self, name, queue):
        threading.Thread.__init__(self)
        self.name = name
        self.queue = queue

    def run(self):
        while True:
            time.sleep(1)  # simulate some work being done
            self.queue.put(f"Item produced by {self.name}")


class Consumer(threading.Thread):
    def __init__(self, name, queue):
        threading.Thread.__init__(self)
        self.name = name
        self.queue = queue

    def run(self):
        while True:
            item = self.queue.get()
            time.sleep(1)  # simulate some work being done
            print(f"Item consumed by {self.name}: {item}")
            self.queue.task_done()


def main():
    queue = ItemQueue()

    producers = []
    for i in range(2):
        producer = Producer(f"Producer_{i}", queue)
        producer.start()
        producers.append(producer)

    consumers = []
    for i in range(3):
        consumer = Consumer(f"Consumer_{i}", queue)
        consumer.start()
        consumers.append(consumer)

    for p in producers:
        p.join()

    for c in consumers:
        c.join()


if __name__ == "__main__":
    main()
```

This Python code uses the `threading` and `queue` modules to implement a producer-consumer design pattern. The `ItemQueue` class represents a shared queue, where items are produced by producers and consumed by consumers. Each producer and consumer is represented as a separate thread that runs indefinitely, producing or consuming items from the queue.

The main function creates multiple instances of producers and consumers, starts them all running concurrently, and then waits for each one to finish using `join()`.