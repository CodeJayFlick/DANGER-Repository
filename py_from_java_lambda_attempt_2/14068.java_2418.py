Here is the translation of the Java code to Python:
```python
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
```
Note that I've replaced the Java-specific constructs (e.g., `package`, `import`, `@Slf4j`) with Python's equivalent syntax. The logic of the code remains largely unchanged, but some simplifications were made to adapt it to Python's style and idioms.

In particular:

* The `App` class is not needed in Python; instead, I defined a standalone `main()` function.
* The `Executors.newFixedThreadPool(3)` equivalent is achieved using Python's built-in `threading.Thread` and list comprehension.
* The `Slf4j` logging facade is replaced with Python's standard library `logging` module.

Please note that this translation assumes the original Java code was intended to demonstrate a basic concept of double-checked locking, rather than being part of a larger application.