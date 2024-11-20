Here is the translation of the given Java code into Python:

```Python
class UnmodifiableListIterator:
    def __init__(self, iterator):
        self.iterator = iterator

    def assign(self, other_iterator):
        raise Exception("Cannot modify this iterator!")

    def decrement(self):
        raise Exception("Cannot modify this iterator!")

    def decrement_by_n(self, n):
        raise Exception("Cannot modify this iterator!")

    def delete(self):
        raise Exception("Cannot modify this iterator!")

    def delete_by_count(self, count):
        raise Exception("Cannot modify this iterator!")

    def increment(self):
        raise Exception("Cannot modify this iterator!")

    def increment_by_n(self, n):
        raise Exception("Cannot modify this iterator!")

    def insert_value(self, value):
        raise Exception("Cannot modify this iterator!")

    def set_value(self, value):
        raise Exception("Cannot modify this iterator!")
```

Note that Python does not have direct equivalents to Java's `public`, `private`, and other access modifiers. In Python, all class members are public by default.