Here is the translation of the Java code to Python:
```
class PcodeExecutionException(Exception):
    def __init__(self, message: str, frame=None, cause=None) -> None:
        super().__init__(message)
        self.frame = frame
        if cause is not None:
            self.__cause__ = cause

    @property
    def frame(self) -> 'PcodeFrame':
        return self._frame

    def __str__(self) -> str:
        return f"PcodeExecutionException: {super().__str__()}"
```
Note that I've used the `Exception` class as a base, since Python's built-in exception classes are not equivalent to Java's `RuntimeException`. Additionally, I've added an `@property` decorator for the `frame` attribute, which allows it to be accessed like a property.