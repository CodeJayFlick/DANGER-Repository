Here is the translation of the Java code to Python:
```
import storage_engine_exception as StorageEngineException

class IoTDBMBean:
    def __init__(self):
        pass

    def stop(self) -> None:
        raise StorageEngineException
```
Note that in Python, we don't need an `@FunctionalInterface` annotation because interfaces are not a first-class citizen like they are in Java. Instead, we define the interface as a class with methods.

Also, I used the `raise` statement to simulate the throwing of an exception in Java. In Python, you can raise any type of exception using the `raise` statement.