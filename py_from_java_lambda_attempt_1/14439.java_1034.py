Here is the translation of the given Java code into equivalent Python:

```Python
import logging

# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class App:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @staticmethod
    def main(args):
        # Simple lazy loader  (not thread safe)
        holder_naive = HolderNaive()
        heavy = holder_naive.get_heavy()
        App().logger.info("heavy={}", heavy)

        # Thread-safe lazy loader, but with heavy synchronization on each access
        holder_thread_safe = HolderThreadSafe()
        another = holder_thread_safe.get_heavy()
        App().logger.info("another={}", another)

        # The most efficient lazy loader utilizing Python 3.5+ features (not Java 8)
        java_8_holder = Java8Holder()
        next = java_8_holder.get_heavy()
        App().logger.info("next={}", next)


class HolderNaive:
    def __init__(self):
        self.heavy = None

    def get_heavy(self):
        if not self.heavy:
            # simulate heavy computation
            import time
            time.sleep(1)
            self.heavy = "Heavy"
        return self.heavy


class HolderThreadSafe:
    def __init__(self):
        self.lock = threading.Lock()
        self.heavy = None

    def get_heavy(self):
        with self.lock:
            if not self.heavy:
                # simulate heavy computation
                import time
                time.sleep(1)
                self.heavy = "Heavy"
            return self.heavy


class Java8Holder:  # This class is not equivalent to the original Java code, it's just a placeholder for demonstration purposes.
    def __init__(self):
        pass

    def get_heavy(self):
        if not hasattr(self, 'heavy'):
            import time
            time.sleep(1)
            self.heavy = "Heavy"
        return getattr(self, 'heavy')
```

Note that the Java 8 Holder class is not equivalent to the original code and has been replaced with a placeholder in Python.