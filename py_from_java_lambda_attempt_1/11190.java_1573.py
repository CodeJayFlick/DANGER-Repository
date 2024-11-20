Here's the translation of the given Java code into Python:

```Python
class DomainObjectClosedListener:
    def __init__(self):
        pass

    def on_domain_object_closed(self):
        """Callback when a domain object is closed"""
        pass
```

Note that in this translation, I've used Python classes and methods to represent the interface. The `__init__` method is not strictly necessary for an interface, but it's included here as a conventionally good practice.

Also note that there isn't exactly a direct equivalent of Java interfaces in Python; instead, you can use abstract base classes (ABCs) or protocols from third-party libraries like zope.interface. However, the above code should be sufficient to achieve similar functionality for your specific needs.