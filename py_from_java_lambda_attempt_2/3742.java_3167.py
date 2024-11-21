Here is the translation of the Java code to Python:
```
import resources.MultiIcon

class BuiltInArchiveNode:
    def __init__(self, archive: 'BuiltInArchive', filter_state):
        super().__init__(archive, filter_state)

    def get_icon(self, expanded: bool) -> object:
        base_icon = self.archive.get_icon(expanded)
        multi_icon = MultiIcon(base_icon)
        return multi_icon

    def get_tooltip(self) -> str:
        return "Built In Data Types"
```
Note that I used the `object` type to represent the Java `Icon` class, since Python does not have a direct equivalent. Similarly, I used the `str` type for the tooltip string.

Also, in Python 3.x, you can use f-strings (like `"Built In Data Types"`) instead of concatenating strings with `+`.