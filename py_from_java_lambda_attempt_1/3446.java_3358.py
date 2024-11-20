Here is the translation of the given Java code into equivalent Python:

```Python
class BookmarkDeleteCmd:
    def __init__(self):
        pass

    @property
    def bookmarks(self):
        return self._bookmarks

    @bookmarks.setter
    def bookmarks(self, value):
        if not isinstance(value, list) or len(value) == 0:
            raise ValueError("Bookmarks must be a non-empty list of Bookmark objects")
        self._bookmarks = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if not isinstance(value, str):
            raise ValueError("Type must be a string")
        self._type = value

    @property
    def category(self):
        return self._category

    @category.setter
    def category(self, value):
        if not isinstance(value, str):
            raise ValueError("Category must be a string")
        self._category = value

    @property
    def addr_set(self):
        return self._addr_set

    @addr_set.setter
    def addr_set(self, value):
        if not isinstance(value, AddressSetView) and value is not None:
            raise ValueError("Addr set must be an instance of AddressSetView or None")
        self._addr_set = value

    def __init__(self, bookmarks=None, addr_set=None, type=None, category=None):
        self.bookmarks = bookmarks
        self.addr_set = addr_set
        self.type = type
        self.category = category

    @property
    def presentation_name(self):
        return self._presentation_name

    @presentation_name.setter
    def presentation_name(self, value):
        if not isinstance(value, str):
            raise ValueError("Presentation name must be a string")
        self._presentation_name = value

    def __init__(self, bookmark=None):
        if bookmark is None:
            raise ValueError("Bookmark cannot be null")
        self.bookmarks = [bookmark]
        self.presentation_name = "Delete Bookmark"

    def apply_to(self, obj):
        program = Program(obj)
        manager = program.get_bookmark_manager()
        if self.bookmarks is not None:
            for bookmark in self.bookmarks:
                manager.remove_bookmark(bookmark)
        elif self.addr_set is not None:
            if self.type is not None:
                if self.category is not None:
                    manager.remove_bookmarks(self.addr_set, self.type, self.category)
                else:
                    manager.remove_bookmarks(self.addr_set, self.type)
            else:
                manager.remove_bookmarks(self.addr_set)

    def get_presentation_name(self):
        return self.presentation_name

class BookmarkManager:
    def remove_bookmark(self, bookmark):
        pass

    def remove_bookmarks(self, bookmarks=None, type=None, category=None):
        if bookmarks is None and (type or category):
            raise ValueError("Bookmarks cannot be null when removing by type/category")
        # implement the actual removal logic here
```

Note that Python does not have direct equivalent of Java's `Command` interface. Also, some methods in your code are private which means they can't be accessed directly from outside their class.