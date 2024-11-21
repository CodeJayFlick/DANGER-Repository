import threading
import time
import logging

logging.basicConfig(level=logging.INFO)

class Item:
    pass

class Inventory:
    def __init__(self, size):
        self.size = size
        self.items = []

    def add_item(self, item):
        while len(self.items) < self.size:
            if not self._add_item(item):
                return False
        return True

    def _add_item(self, item):
        # simulate a lock acquisition (double-checked locking)
        if threading.current_thread().lock.acquire():
            try:
                self.items.append(item)
                return True
            finally:
                threading.current_thread().lock.release()
        return False


def main():
    inventory = Inventory(1000)

    def add_item(i):
        while inventory.add_item(Item()):
            logging.info("Adding another item")

    threads = []
    for i in range(3):
        t = threading.Thread(target=add_item, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
