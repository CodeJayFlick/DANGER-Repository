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
Note that I've used Python's `@property` decorator to create a read-only property for the `value` attribute. This is equivalent to Java's getter method. Similarly, the setter method has been implemented using the same syntax.

Also, in Python, we don't need to explicitly define constructors like Java does with its `public class SingleValueModel { ... }`. Instead, we use an initializer (`__init__`) method that gets called when an instance of the class is created.