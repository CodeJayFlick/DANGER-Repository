Here is the translation of the Java code to Python:
```
class Counter:
    def __init__(self):
        self.map = {}

    def clear(self):
        self.map.clear()

    def get_and_remove(self, name):
        if name not in self.map:
            return 0
        count = self.map.pop(name)
        return count

    def total_count(self):
        total = 0
        for key in self.map.keys():
            count = self.map[key]
            total += count
        return total

    def increment(self, name):
        if name not in self.map:
            self.map[name] = 0
        self.map[name] += 1

class Count:
    def __init__(self):
        self.count = 0

    def increment(self):
        self.count += 1
```
Note that I used the `__init__` method to initialize the instance variables, and I replaced the Java-style getters and setters with Python's attribute access syntax. I also removed the unnecessary type annotations (e.g., `String`, `int`) since they are not needed in Python.