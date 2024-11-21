Here is the translation of the Java interface `ReferenceListener` into a Python class:

```python
class ReferenceListener:
    def mem_reference_added(self, reference):
        """Notification that the given memory reference has been added."""
        pass  # Implement this method in your subclass

    def mem_reference_removed(self, reference):
        """Notification that the given memory reference has been removed."""
        pass  # Implement this method in your subclass

    def mem_reference_type_changed(self, new_ref, old_ref):
        """Notification that the reference type on the given memory reference has changed."""
        pass  # Implement this method in your subclass

    def mem_reference_primary_set(self, reference):
        """Notification that the given memory reference has been set as the primary reference."""
        pass  # Implement this method in your subclass

    def mem_reference_primary_removed(self, reference):
        """Notification that the given memory reference is no longer the primary reference."""
        pass  # Implement this method in your subclass

    def stack_reference_added(self, reference):
        """Notification that the given stack reference has been added."""
        pass  # Implement this method in your subclass

    def stack_reference_removed(self, reference):
        """Notification that the given stack reference has been removed."""
        pass  # Implement this method in your subclass

    def external_reference_added(self, reference):
        """Notification that the given external reference has been added."""
        pass  # Implement this method in your subclass

    def external_reference_removed(self, reference):
        """Notification that the given external reference has been removed."""
        pass  # Implement this method in your subclass

    def external_reference_name_changed(self, reference):
        """Notification that the external program name in the reference has changed."""
        pass  # Implement this method in your subclass
```

Note that I've kept the Python methods as simple stubs (`pass`) since they don't have any specific implementation. You would need to create a concrete subclass of `ReferenceListener` and implement these methods according to your needs.