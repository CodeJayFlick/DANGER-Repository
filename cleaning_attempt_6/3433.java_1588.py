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

