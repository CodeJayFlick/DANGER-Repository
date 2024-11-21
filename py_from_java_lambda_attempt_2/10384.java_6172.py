Here is the translation of the Java code to Python:
```
class FixedSizeStack:
    def __init__(self, max_size):
        self.max_size = max_size
        self.stack = []

    def push(self, item):
        if len(self.stack) > self.max_size:
            self.stack.pop(0)
        return self.stack.append(item)

    def add(self, item):
        if len(self.stack) > self.max_size:
            self.stack.pop(0)
        return self.stack.append(item)

    def remove(self, index):
        return self.stack.pop(index)
```
Note that I've used the `list` class from Python's standard library to implement the stack. The `push`, `add`, and `remove` methods have been translated accordingly.

Also, since there is no equivalent of Java's generics in Python, I've omitted the type parameter `<E>` from the class definition.