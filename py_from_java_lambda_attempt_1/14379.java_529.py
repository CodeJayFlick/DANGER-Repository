Here is the translation of the given Java code into Python:

```Python
class AbstractFilter:
    def __init__(self):
        self.next = None

    def set_next(self, filter):
        self.next = filter

    def get_next(self):
        return self.next

    def get_last(self):
        last = self
        while last.get_next() is not None:
            last = last.get_next()
        return last

    def execute(self, order):
        if self.get_next():
            return self.get_next().execute(order)
        else:
            return ""
```

Note that Python does not have a direct equivalent to Java's `abstract` keyword. In this translation, I've removed the abstract modifier from the class definition since it is not necessary in Python.