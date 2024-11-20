Here is the translation of the given Java code into equivalent Python:

```Python
# No license information in this example.

from abc import ABC, abstractmethod

class TargetProcess(ABC):
    PID_ATTRIBUTE_NAME = "pid"

    @abstractmethod
    def get_pid(self) -> int:
        pass


if __name__ == "__main__":
    # This is just an example of how you might use the class.
    class MyTargetProcess(TargetProcess):
        def get_pid(self) -> int:
            return 123

    my_process = MyTargetProcess()
    print(my_process.get_pid())
```

Note that Python does not have direct equivalents for Java's interfaces, abstract classes or annotations. In this translation, I've used an abstract class (`ABC`) to define the `get_pid` method as abstract (i.e., it must be implemented by any subclass).