Here is the translation of the Java code to Python:
```
class ObjectPool(T):
    def __init__(self):
        self.available = set()
        self.in_use = set()

    def create(self) -> T:
        # This method should be implemented by subclasses
        pass

    def check_out(self) -> T:
        if not self.available:
            instance = self.create()
            self.available.add(instance)
        return next(iter(self.available))
        self.available.remove(next(iter(self.available)))
        self.in_use.add(next(iter(self.available)))

    def check_in(self, instance: T):
        self.in_use.remove(instance)
        self.available.add(instance)

    def __str__(self) -> str:
        return f"Pool available={len(self.available)} inUse={len(self.in_use)}"
```
Note that I've used the `set` type from Python's built-in `collections` module to represent the sets of available and in-use objects. The rest of the code is straightforward translation, with some minor adjustments for Python's syntax.

Also note that the `create()` method is abstract in Java, but in Python, we can't have an abstract method like this. Instead, I've left it as a placeholder for subclasses to implement.