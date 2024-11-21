Here is the translation of the Java code to Python:
```
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

class SingleValueModel:
    def __init__(self):
        self.value = None

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value
```
Note that I've used Python's `@property` decorator to create a read-only property for the `value` attribute. This is equivalent to Java's getter method.

Also, in Python, we don't need explicit setter and getter methods like in Java. The `@property` decorator allows us to define custom behavior when accessing or setting an attribute.