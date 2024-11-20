Here is a translation of the Java code into equivalent Python code:

```Python
class StickToTopLinearLayoutManager:
    def __init__(self):
        pass  # No direct equivalent in Python for Context parameter.

    def on_items_added(self, recyclerView, positionStart, itemCount):
        super().on_items_added(recyclerView, positionStart, itemCount)
        if positionStart == 0 and self.find_first_completely_visible_item_position() <= itemCount:
            self.scrollToPosition(0)

class LinearLayoutManager:
    pass

# No direct equivalent in Python for the following Java classes.
class RecyclerView:
    def __init__(self):
        pass
```

Please note that this translation is not a straightforward conversion, as some concepts and features from Java do not have direct equivalents in Python.