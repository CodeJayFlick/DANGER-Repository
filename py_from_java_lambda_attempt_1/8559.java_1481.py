Here is the translation of the given Java code into equivalent Python:

```Python
class ObjectOrientedClassLayout:
    MEMBERS_ONLY = ("Legacy",)
    BASIC_SIMPLE_COMPLEX = ("Complex with Basic Fallback",)
    SIMPLE_COMPLEX = ("Complex with Simple Fallback",)
    COMPLEX = ("Complex Always",)

    def __str__(self):
        return self.label

ObjectOrientedClassLayout.__init__ = lambda self, label: setattr(self, 'label', label)
```

Note that Python does not have an exact equivalent to Java's enum. The above code uses a class with static variables and a custom `__init__` method to mimic the behavior of the original Java code.