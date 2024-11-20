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
