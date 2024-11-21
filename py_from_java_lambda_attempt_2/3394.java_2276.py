Here is the translation of the Java interface `AnalysisWorker` into a Python class:

```python
class AnalysisWorker:
    def analysis_worker_callback(self, program: 'Program', worker_context: object, monitor: 'TaskMonitor') -> bool:
        """Analysis worker callback which performs the desired changes to program while analysis is suspended."""
        raise NotImplementedError

    def get_worker_name(self) -> str:
        """Returns worker name to be used for analysis task monitor. Name should be very short."""
        raise NotImplementedError
```

Note that I've kept the method signatures and docstrings similar to the original Java code, but with some minor adjustments to fit Python's syntax and conventions.

In particular:

* The `public` access modifier is not needed in Python, as all methods are public by default.
* The type annotations for the method parameters (`Program`, `Object`, etc.) are added using Python 3.5+ style type hints (e.g., `'Program'`). This allows for static type checking and IDE integration.
* I've used the `raise NotImplementedError` statement to indicate that these methods must be implemented by any subclass of `AnalysisWorker`. In Java, this would correspond to abstract methods with no implementation.

You can use this Python class as a starting point to implement your own analysis worker.