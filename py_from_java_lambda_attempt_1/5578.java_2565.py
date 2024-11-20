Here is the translation of the Java interface `ListingModelListener` to a Python class:

```python
class ListingModelListener:
    def model_size_changed(self):
        """Called whenever the number of indexes changed"""
        pass  # implement this method in your subclass

    def data_changed(self, update_immediately: bool) -> None:
        """
        Called when the data at an index or range of indexes changes.
        
        :param update_immediately: True to immediately update the listing upon change
        """
        pass  # implement this method in your subclass
```

Note that I've used Python's `pass` statement as a placeholder for methods that need to be implemented by subclasses. In Java, these would have been abstract methods declared without an implementation.