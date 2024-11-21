Here is the translation of the Java code to Python:
```
class RecorderSimpleRegisterSet:
    def __init__(self, recorder):
        self.recorder = recorder
        self.bank = None  # initialize bank as None

    def update_registers(self, new_regs, old_regs):
        self.bank = new_regs
```
Note that I've used the following Python concepts to translate the Java code:

* Classes and objects: In Python, we define classes using the `class` keyword, just like in Java. We also create instances of these classes by calling their constructors (or `__init__` methods).
* Attributes: In Python, attributes are accessed using dot notation (`self.attribute_name`). This is similar to how you access fields in Java.
* Methods: In Python, we define functions inside a class definition using the same syntax as regular Python functions. We can call these methods on instances of the class.

I've also removed some boilerplate code that was present in the original Java file (e.g., copyright notices and package declarations).