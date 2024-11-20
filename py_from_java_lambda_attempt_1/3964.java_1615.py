Here is the translation of the given Java code into equivalent Python:

```Python
# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

class InstructionTableObserver:
    def __init__(self):
        pass

    def changed(self):
        # method to be implemented by subclasses
        pass


from abc import ABC, abstractmethod

class Observer(ABC):
    @abstractmethod
    def update(self):
        pass
```

Please note that Python does not have direct equivalent of Java's interface or observer pattern. However, we can achieve similar functionality using classes and inheritance in Python.

In the above code:

- The `InstructionTableObserver` class is a custom implementation of Observer pattern.
- It has an abstract method `changed()` which should be implemented by any subclass that wants to receive notifications when the `InstructionTable` changes.
- We have also defined an abstract base class `Observer` with an abstract method `update()`. This can be used as a parent for classes that want to implement Observer pattern.