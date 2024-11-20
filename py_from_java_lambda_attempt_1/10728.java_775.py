Here is the translation of the Java code to Python:
```
class DefaultGEdge:
    def __init__(self, start, end):
        self.start = start
        self.end = end

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end

    def __str__(self):
        return f"[{self.start}, {self.end}]"

    def __hash__(self):
        prime = 31
        result = 1
        if self.end is not None:
            result *= prime + hash(self.end)
        if self.start is not None:
            result *= prime + hash(self.start)
        return result

    def __eq__(self, other):
        if self is other:
            return True
        if other is None:
            return False
        if type(self) != type(other):
            return False

        other = DefaultGEdge(other.get_start(), other.get_end())
        return hash(self.start) == hash(other.start) and hash(self.end) == hash(other.end)
```
Note that I used the `f` string notation to create a formatted string in the `__str__` method, which is equivalent to Java's `toString()` method. Additionally, Python does not have an explicit `hashCode()` method like Java does; instead, we can use the built-in `hash()` function to generate a hash value for each object. The `equals()` method has been translated to Python as well, using the same logic and syntax.