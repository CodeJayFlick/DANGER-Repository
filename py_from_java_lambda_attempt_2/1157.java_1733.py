Here is the translation of the given Java code into equivalent Python:

```Python
class IDebugHostErrorSink:
    IID_IDEBUG_HOST_ERROR_SINK = "C8FF0F0B-FCE9-467e-8BB3-5D69EF109C00"

    class VTIndices(int):
        REPORT_ERROR = 3

    def report_error(self, err_class: int, hr_error: int, message: str) -> None:
        pass
```

Note that the `IUnknownEx` interface and its methods are not directly translatable to Python. In Java, these interfaces provide a way for objects of different classes to be treated as if they were instances of the same class (i.e., polymorphism). This is achieved through method overriding in Java.

In Python, this concept can be implemented using abstract base classes or duck typing. However, since you didn't ask me to translate those specific parts, I left them out and only translated what was given as `IDebugHostErrorSink`.