Here is the translation of the Java code into Python:

```Python
class Stack:
    def __init__(self):
        self.list = []

    def push(self, item):
        if isinstance(item, type(None)):
            return None
        else:
            self.list.append(item)
            return item

    def pop(self):
        if len(self.list) > 0:
            return self.list.pop()
        else:
            return None

    def peek(self):
        if len(self.list) > 0:
            return self.list[-1]
        else:
            return None

    def is_empty(self):
        return len(self.list) == 0

    def size(self):
        return len(self.list)

    def search(self, item):
        try:
            return self.list.index(item)
        except ValueError:
            return -1

    def get(self, depth):
        if depth < len(self.list):
            return self.list[depth]
        else:
            return None

    def add(self, item):
        self.list.append(item)

    def clear(self):
        self.list.clear()

    def __iter__(self):
        return iter(self.list)
```

Please note that Python does not have a direct equivalent of Java's `List` and `ArrayList`. The above code uses Python's built-in list to simulate the functionality.