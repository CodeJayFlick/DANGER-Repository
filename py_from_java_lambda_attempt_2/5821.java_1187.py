Here is the translation of the Java interface `ExecutionListener` to a Python class:

```python
class ExecutionListener:
    def step_completed(self, test_runner):
        pass  # implement this method in your subclass

    def log_write(self, test_runner: 'EmulatorTestRunner', address: int, size: int, values: bytes) -> None:
        pass  # implement this method in your subclass

    def log_read(self, test_runner: 'EmulatorTestRunner', address: int, size: int, values: bytes) -> None:
        pass  # implement this method in your subclass
```

Note that I've used the `pass` statement to indicate where you would need to add implementation for each of these methods. You can create a subclass of `ExecutionListener` and override these methods as needed.

Also, I've kept the type hints (`test_runner: 'EmulatorTestRunner'`, etc.) to make it clear what types are expected by each method.