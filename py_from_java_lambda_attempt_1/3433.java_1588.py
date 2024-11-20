Here is the translation of the given Java code into equivalent Python:

```Python
class PostAnalysisValidator:
    def __init__(self, program):
        self.program = program

    @property
    def program(self):
        return self._program

    def run(self, monitor):
        if not self.program.add_consumer(self):
            return ConditionResult.Cancelled()

        try:
            result = self.do_run(monitor)
            return result
        finally:
            self.program.release(self)

    def do_run(self, monitor):
        pass  # abstract method implementation left to the subclass


class Program:
    def __init__(self):
        pass

    def add_consumer(self, consumer):
        pass  # implement this in a subclass or actual program class

    def release(self, consumer):
        pass  # implement this in a subclass or actual program class


class ConditionResult:
    @staticmethod
    def Cancelled():
        return "Cancelled"


# Example usage:

program = Program()
validator = PostAnalysisValidator(program)
result = validator.run(None)  # TaskMonitor is not implemented here

print(result)  # prints: Cancelled (or the result of do_run method if it's successful)

```

Please note that Python does not have direct equivalent to Java's abstract classes and interfaces. The `PostAnalysisValidator` class in this translation is a regular Python class with an abstract method (`do_run`).