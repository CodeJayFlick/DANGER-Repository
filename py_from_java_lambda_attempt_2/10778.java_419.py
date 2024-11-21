Here's the translation of the given Java interface into Python:

```Python
class PathHighlightListener:
    def __init__(self):
        pass

    def path_highlight_changed(self, hover_change: bool) -> None:
        """
        Called when a path is highlighted.

        Args:
            hover_change (bool): True if the change path is a hover change; False if the changed path
                                 is a selection change.
        """
        pass
```

Note that in Python, we don't have an equivalent to Java's `public` and `interface`. Instead, we define classes using the `class` keyword. The methods within this class are defined with indentation (just like functions).