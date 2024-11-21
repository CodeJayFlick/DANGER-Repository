Here is the translation of the Java code into Python:

```Python
class CombinedTableFilter:
    def __init__(self, *filters):
        self.filters = list(filters)

    def accepts_row(self, row_object):
        for filter in self.filters:
            if not filter.accepts_row(row_object):
                return False
        return True

    @property
    def is_empty(self):
        return len(self.filters) == 0

    @property
    def filter_count(self):
        return len(self.filters)

    def get_filter(self, index):
        try:
            return self.filters[index]
        except IndexError:
            raise ValueError("Index out of range")

    def is_sub_filter_of(self, table_filter):
        if not isinstance(table_filter, CombinedTableFilter):
            return False
        other = table_filter
        if len(self.filters) != len(other.filters):
            return False
        if len(self.filters) == 0:
            return False
        for i in range(len(self.filters)):
            if not self.get_filter(i).is_sub_filter_of(other.get_filter(i)):
                return False
        return True

    def has_column_filter(self, model_index):
        for filter in self.filters:
            if filter.has_column_filter(model_index):
                return True
        return False

    def __hash__(self):
        raise NotImplementedError("Not meant to put in hashing structures; the data for equals may change over time")

    def __eq__(self, obj):
        if self is obj:
            return True
        if obj is None:
            return False
        if type(self) != type(obj):
            return False

        other = obj
        if set(self.filters) != set(other.filters):
            return False
        return True
```

Please note that Python does not have direct equivalent of Java's generics. The `T` in the original code is replaced with a simple placeholder, and you would need to specify the type when creating an instance of this class.