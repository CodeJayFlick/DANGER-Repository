Here's your Java code translated into Python:

```Python
import logging

class BatchLogReader:
    def __init__(self, buffer):
        self.plans = self.read_logs(buffer)
        self.plan_iterator = iter(self.plans)

    def read_logs(self, buffer):
        plans = []
        while True:
            try:
                plan = PhysicalPlan.create_from_buffer(buffer)
                plans.append(plan)
            except (IOError, IllegalPathException) as e:
                logging.error("Cannot deserialize PhysicalPlans from ByteBuffer, ignore remaining logs", e)
                self.file_corrupted = True
                break

    def close(self):
        pass  # nothing to be closed

    def has_next(self):
        return bool(self.plan_iterator)

    def next(self):
        return next(self.plan_iterator)

    @property
    def file_corrupted(self):
        return self._file_corrupted

    @file_corrupted.setter
    def file_corrupted(self, value):
        self._file_corrupted = value


class PhysicalPlan:
    @classmethod
    def create_from_buffer(cls, buffer):  # You need to implement this method
        pass


# Usage example:

buffer = bytearray(1024)  # Replace with your ByteBuffer

reader = BatchLogReader(buffer)

while reader.has_next():
    plan = reader.next()
    print(plan)
```

Note that I've used Python's built-in `logging` module for logging, and implemented the `PhysicalPlan.create_from_buffer()` method as a placeholder. You'll need to implement this method according to your specific requirements.

Also note that in Java, you would typically use an interface (`ILogReader`) with methods like `hasNext()`, `next()`, etc., but Python doesn't have built-in support for interfaces; instead, we can define these methods directly on the class.