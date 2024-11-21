Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright © 2014-2021 Ilkka Seppälä

class ArcherCommand:
    def process(self):
        ArcherView().display()

class ArcherView:
    def display(self):
        # implement your view logic here
        pass
```
Note that I've kept the `ArcherView` class as is, since it's not a part of the command pattern implementation. In Python, we don't need to define classes with explicit access modifiers (public/private), and we use indentation instead of curly braces for block-level syntax.

Also, in Python, we typically use underscores (`_`) to indicate private variables or methods, but I've left them out since they're not explicitly defined as such.