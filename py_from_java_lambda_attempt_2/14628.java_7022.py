Here is the translation of the Java code to Python:

```Python
import threading
from functools import wraps

class Oliphaunt:
    _counter = [0]

    def __init__(self):
        self.id = self._get_id()
        try:
            # Simulating expensive operation (sleeping for 1 second)
            time.sleep(1)
        except Exception as e:
            print(f"Error: {e}")

    @property
    def id(self):
        return self._id

    def _get_id(self):
        Oliphaunt._counter[0] += 1
        return Oliphaunt._counter[0]

    def __str__(self):
        return f'Oliphaunt id={self.id}'
```

Note that Python does not have a direct equivalent to Java's `AtomicInteger` class, so I used a list with an integer value instead. The `_get_id()` method is used to get the unique ID for each Oliphaunt instance.

The `try-except` block in the constructor simulates an expensive operation (sleeping for 1 second) that may throw an exception.