Here is the translation of the given Java interface into a Python class:

```Python
class DomainObjectListener:
    def __init__(self):
        pass

    def domain_object_changed(self, ev):
        """Method called when a change is made to the domain object."""
        # Add your code here. This method should be implemented by any subclass.
```

Note that in Python, we don't have an equivalent of Java's `interface` keyword. Instead, we define classes and methods as needed. The `domain_object_changed` method is defined with a docstring to provide documentation for the method.