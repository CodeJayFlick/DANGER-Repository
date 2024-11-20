Here is the translation of the Java code to Python:

```Python
class TableSortingContext:
    def __init__(self, sort_state: 'TableSortState', comparator):
        self.sort_state = sort_state
        self.comparator = comparator

    @property
    def get_comparator(self):
        return self.comparator

    @property
    def get_sort_state(self):
        return self.sort_state

    def is_unsorted(self):
        return self.sort_state.is_unsorted()

    def is_reverse_of(self, other_context: 'TableSortingContext'):
        if len(self.sort_state) != 1:
            return False
        
        for item in self.sort_state:
            column_index = item.get_column_model_index()
        
        for other_item in other_context.sort_state:
            other_column_index = other_item.get_column_model_index()

        if column_index != other_column_index:
            return False

        return not (item.get_sort_direction() == other_item.get_sort_direction())

    def __eq__(self, obj):
        if self is obj:
            return True
        
        if type(obj) != TableSortingContext:
            return False
        
        other = obj
        if not self.sort_state.__eq__(other.sort_state):
            return False

        return True

    def __hash__(self):
        result = 1
        result *= 31 + (0 if self.comparator is None else hash(self.comparator))
        result *= 31 + (0 if self.sort_state is None else hash(self.sort_state))

        return result

    def __str__(self):
        return str(self.sort_state)
```

Note that I've used Python's type hinting to indicate the types of variables and function parameters. This can help with code readability and catch potential errors at runtime.