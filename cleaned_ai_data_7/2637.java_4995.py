class MethodProtector:
    def __init__(self):
        self.in_use = False

    class TemperamentalCallable:
        def run(self) -> None:
            pass  # implement this method in subclasses

    def take(self, callable: TemperamentalCallable[Exception]) -> None:
        if self.in_use:
            return
        try:
            self.in_use = True
            callable.run()
        finally:
            self.in_use = False

    def avoid(self, callable: TemperamentalCallable[Exception]) -> None:
        if self.in_use:
            return
        callable.run()

# Example usage:
class MyCallable(TemperamentalCallable):
    def run(self) -> None:
        print("Running my callable!")

protector = MethodProtector()
callable = MyCallable()
try:
    protector.take(callable)
except Exception as e:
    print(f"Error: {e}")

protector.avoid(callable)  # runs the callable without taking it
