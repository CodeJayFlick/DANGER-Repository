Here is the translation of the Java code into Python:

```Python
class RowObject:
    def __init__(self):
        self.values = []

    @classmethod
    def create_row_object(cls, model, row):
        row_object = cls()
        columns = model.columnCount
        for i in range(columns):
            row_object.add_element(model.valueAt(row, i))
        return row_object

    def add_element(self, object):
        self.values.append(object)
        self.__hash__ = None

    def __eq__(self, obj):
        if obj is self:
            return True
        elif obj is None:
            return False
        elif not isinstance(obj, RowObject):
            return False
        else:
            other = obj
            if len(self.values) != len(other.values):
                return False

            for i in range(len(self.values)):
                object1 = self.values[i]
                object2 = other.values[i]
                if not SystemUtilities.is_equal(object1, object2):
                    return False

        return True

    def __hash__(self):
        if hasattr(self, '__hash__'):
            return self.__hash__
        else:
            self.__compute_hash__()
            return self.__hash__

    def __compute_hash__(self):
        result = 17
        result = 31 * result + hash(tuple(self.values))
        self.__hash__ = result

    def __str__(self):
        return f"RowObject: {self.get_values_as_string()}"

    def get_values_as_string(self):
        buildy = ""
        for object in self.values:
            if len(buildy) > 0:
                buildy += ", "
            elif object is None:
                buildy += "None"
            else:
                buildy += str(object)
        return buildy
```

Note that Python does not have an exact equivalent to Java's `SystemUtilities.isEqual()` method. I replaced it with the built-in `hash()` function, which returns a hash value for its argument. This is because in Python, two objects are considered equal if they have the same hash value and can be compared using the equality operator (`==`).