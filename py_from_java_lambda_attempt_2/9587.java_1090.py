Here's the translation of the given Java interface into a Python equivalent:

```Python
from typing import Any

class FieldOverlayListener:
    """Interface implemented by objects that want to be notified when an overlay is removed from the FieldPanel."""

    def field_overlay_removed(self, comp: Any) -> None:
        """
        Called when the an existing component is removed from the FieldPanel.
        
        :param comp: The overlay component that was removed.
        """
```

Note that Python does not have a direct equivalent to Java's interface concept. Instead, we can use abstract base classes (ABCs) or protocols (in Python 3.8 and later). However, since you're looking for a straightforward translation of the given code into Python, I've chosen to represent it as a class with an abstract method (`field_overlay_removed`).