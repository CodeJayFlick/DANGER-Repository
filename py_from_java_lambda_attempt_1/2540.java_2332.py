Here is the translation of the Java interface ` TraceAddressSnapRangePropertyMap` to a Python class:

```python
class TraceAddressSnapRangePropertyMap:
    def get_name(self):
        pass  # implement this method in your subclass

    def get_register_space(self, thread: 'TraceThread', create_if_absent=False) -> 'RegisterSpace':
        pass  # implement this method in your subclass

    def get_register_space(self, frame: 'StackFrame', create_if_absent=False) -> 'RegisterSpace':
        pass  # implement this method in your subclass


class RegisterSpace:
    pass


class TraceThread:
    pass


class StackFrame:
    pass
```

Note that I've kept the Python class and methods abstract by leaving them as `pass` statements. This is because the original Java interface was also abstract, meaning it only defined a contract for its subclasses to implement.

In Python, we don't have direct equivalents of Java interfaces or classes with abstract methods. Instead, we use abstract base classes (ABCs) from the `abc` module to define an abstract class that can be subclassed. However, since you didn't ask me to create ABCs in this case, I've simply left the Python code as a set of placeholder classes and methods for now.

If you want to add more functionality or concrete implementations to these classes, feel free to modify them accordingly!