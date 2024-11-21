Here is the translation of the Java code to Python:
```
class NullTableFilter:
    def accepts_row(self, row_object):
        return True

    def is_sub_filter_of(self, table_filter):
        return False

    def is_empty(self):
        return True

    def __eq__(self, obj):
        if self is obj:
            return True
        elif obj is None:
            return False
        elif type(self) != type(obj):
            return False
        else:
            return True

    def __hash__(self):
        return hash(type(self))
```
Note that I've removed the generics (`<ROW_OBJECT>`) as Python does not have a direct equivalent. Instead, you can use any object type (e.g., `object`, `str`, etc.) and pass it to the methods.

Also, I've kept the method names similar to the original Java code for clarity, but in Python, it's common to use snake_case instead of camelCase for variable and function names.