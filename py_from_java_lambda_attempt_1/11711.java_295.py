Here is the translation of the given Java code into Python:

```Python
class PatternValue:
    def __init__(self, location):
        pass

    def gen_pattern(self, val):
        raise NotImplementedError("Subclasses must implement this method")

    def list_values(self, values_list):
        values_list.append(self)

    def get_min_max(self, min_val_list, max_val_list):
        min_val_list.append(self.min_value())
        max_val_list.append(self.max_value())

    def get_sub_value(self, replace_list, position):
        return replace_list[position.get()] + 1

    @property
    def min_value(self):
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def max_value(self):
        raise NotImplementedError("Subclasses must implement this method")
```

Note that Python does not have direct equivalents of Java's `abstract` and `@Override` keywords. The `gen_pattern`, `min_value`, and `max_value` methods are declared as abstract in the original code, but their implementation is left to subclasses in Python.