Here is the translation of the Java interface `ErrorLogger` to a Python class:

```python
class ErrorLogger:
    def trace(self, originator: object, message: object) -> None:
        pass  # implement logging logic here

    def trace(self, originator: object, message: object, throwable: Exception) -> None:
        pass  # implement logging logic here

    def debug(self, originator: object, message: object) -> None:
        pass  # implement logging logic here

    def debug(self, originator: object, message: object, throwable: Exception) -> None:
        pass  # implement logging logic here

    def info(self, originator: object, message: object) -> None:
        pass  # implement logging logic here

    def info(self, originator: object, message: object, throwable: Exception) -> None:
        pass  # implement logging logic here

    def warn(self, originator: object, message: object) -> None:
        pass  # implement logging logic here

    def warn(self, originator: object, message: object, throwable: Exception) -> None:
        pass  # implement logging logic here

    def error(self, originator: object, message: object) -> None:
        pass  # implement logging logic here

    def error(self, originator: object, message: object, throwable: Exception) -> None:
        pass  # implement logging logic here
```

Note that I've used the `pass` statement to indicate where you would typically put your implementation code. You'll need to fill in the actual logging logic for each method.