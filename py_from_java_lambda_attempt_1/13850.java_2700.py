Here is the translation of the Java code to Python:

```Python
class CallbackTest:
    def __init__(self):
        self.calling_count = 0

    def test(self):
        callback = lambda: self.calling_count += 1

        task = SimpleTask()

        assert self.calling_count == 0, "Initial calling count of 0"

        task.execute_with(callback)

        assert self.calling_count == 1, "Callback called once"

        task.execute_with(callback)

        assert self.calling_count == 2, "Callback called twice"


class SimpleTask:
    def execute_with(self, callback):
        pass
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, you would typically define your test methods using the same naming convention as other methods in your class (e.g., `test_callback`).