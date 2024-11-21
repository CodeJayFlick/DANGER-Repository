Here is the translation of the Java code into Python:

```Python
class DummyListingFGVertex:
    def __init__(self, controller, address_set_view, flow_type, is_entry):
        super().__init__(controller, address_set_view, flow_type, is_entry)

    def __str__(self):
        return f"Dummy {super().__str__()}"


def equals(self, obj):
    return self == obj
```

Note that Python does not have an exact equivalent of Java's `@Override` annotation. In Python, you can use the built-in `__init__`, `__str__`, and `equals` methods to achieve similar functionality.

Also note that in Python, we don't need to specify types for method parameters or return values like we do in Java.