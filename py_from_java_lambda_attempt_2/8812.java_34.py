Here is the translation of the Java interface into a Python class:

```Python
class AssociationHook:
    def association_accepted(self, association):
        """Called whenever an association has been accepted."""
        pass  # implement your logic here

    def association_cleared(self, association):
        """Called whenever an association has been cleared from the accepted state."""
        pass  # implement your logic here

    def markup_item_status_changed(self, markup_item):
        """Called whenever a markupItem's status changes."""
        pass  # implement your logic here
```

Note that in Python, we don't have interfaces like Java. Instead, we use abstract base classes (ABCs) or protocols to define the structure of an object without providing any implementation. However, since you're asking for a direct translation from Java interface into Python code, I've used a class with methods as above.