Here is the translation of the Java interface into Python:

```Python
class CoordinatedListingPanelListener:
    def __init__(self):
        pass

    def listing_closed(self) -> bool:
        """Notifies the listener that it's associated listing panel should get closed.
        
        Returns: 
            True if the listener actually closes a listing panel."""
        return False  # default implementation, you would override this in your subclass

    def active_program_changed(self, active_program):
        pass
```

Note that Python does not have direct support for interfaces like Java. Instead, we define an abstract base class (ABC) with methods to be implemented by subclasses.