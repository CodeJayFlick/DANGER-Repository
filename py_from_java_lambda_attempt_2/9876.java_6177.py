Here's your Java interface translated into a Python class:

```Python
class VariableColumnTableModel:
    @staticmethod
    def from_model(m):
        unwrapped = RowObjectTableModel.unwrap(m)
        if isinstance(unwrapped, VariableColumnTableModel):
            return unwrapped
        else:
            return None

    def get_column_display_name(self, column):
        pass  # implement this method in your subclass

    def get_column_description(self, column):
        pass  # implement this method in your subclass

    def get_unique_identifier(self, column):
        pass  # implement this method in your subclass

    def get_default_column_count(self):
        return -1  # default value; override in your subclass if needed

    def is_default_column(self, model_index):
        return False  # default value; override in your subclass if needed

    def is_visible_by_default(self, model_index):
        return False  # default value; override in your subclass if needed
```

Note that I've made the methods abstract by not providing any implementation. You'll need to create a concrete class that inherits from `VariableColumnTableModel` and implements these methods according to your needs.

Also note that Python doesn't have an exact equivalent of Java's interfaces, but we can achieve similar functionality using abstract base classes (ABCs) or protocols as implemented in some other languages.