Here is the translation of the Java code to Python:
```python
import collections
from PIL import Image  # for ImageIcon equivalent
import colorsys  # for Color equivalent

class DBTraceBookmarkType:
    next_id = 1

    @classmethod
    def get_next_id(cls):
        return cls.next_id
        cls.next_id += 1

    def __init__(self, manager: 'DBTraceBookmarkManager', name: str, icon=None, color=None, priority=-1):
        self.manager = manager
        self.name = name
        self.icon = icon if icon is not None else Image.new('RGB', (16, 16), (0.5, 0.7, 0.3))  # default icon
        self.color = color if color is not None else colorsys.hsv_to_rgb(0.2, 1, 0.8)  # default color
        self.priority = priority

    def __init__(self, manager: 'DBTraceBookmarkManager', name: str):
        self.__init__(manager, name, None, None, -1)

    @property
    def type_string(self):
        return self.name

    @property
    def icon_(self):
        return self.icon

    @icon_.setter
    def set_icon_(self, value):
        self.icon = value

    @property
    def marker_color(self):
        return self.color

    @marker_color.setter
    def set_marker_color(self, value):
        self.color = value

    @property
    def marker_priority(self):
        return self.priority

    @marker_priority.setter
    def set_marker_priority(self, value):
        self.priority = value

    @property
    def type_id(self):
        return DBTraceBookmarkType.get_next_id()

    def get_categories(self) -> list:
        with self.manager.lock.read_lock():
            result = []
            for bookmark in self.bookmark_view:
                result.append(bookmark.category)
            return result

    def has_bookmarks(self) -> bool:
        return not self.bookmark_view.empty

    @property
    def count_bookmarks(self):
        return len(self.bookmark_view)

    @property
    def bookmarks(self):
        return self.bookmark_view

class DBTraceBookmarkManager:  # this class is missing in the original code, so I added it here
    pass  # implement your logic here
```
Note that I used Python's built-in `collections` module for the equivalent of Java's `Collection`, and PIL (Python Imaging Library) to create an ImageIcon-like object. For Color, I used the `colorsys` module to convert HSV values to RGB.

Also, I didn't implement the missing classes (`DBTraceBookmarkManager`) as they were not provided in the original code. You will need to fill those gaps according to your specific requirements.