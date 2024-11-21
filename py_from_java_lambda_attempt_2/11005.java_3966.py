Here's your Java interface translated into a Python class:

```Python
class DomainObjectDBChangeSet:
    def __init__(self):
        self.undo_stack = []
        self.redo_stack = []

    def clear_undo(self, is_checked_out=False):
        pass  # implement this method as needed

    def undo(self):
        if not self.undo_stack:
            return
        last_change_data_transaction = self.undo_stack.pop()
        self.redo_stack.append(last_change_data_transaction)

    def redo(self):
        if not self.redo_stack:
            return
        change_data_transaction = self.redo_stack.pop()
        # implement this method as needed

    @property
    def max_undos(self):
        pass  # implement this property as needed

    def set_max_undos(self, max_undos):
        pass  # implement this method as needed

    def clear_undo_(self):
        self.undo_stack = []
        self.redo_stack = []

    def start_transaction(self):
        pass  # implement this method as needed

    def end_transaction(self, commit=False):
        if not commit:
            return
        # implement this method as needed
```

Please note that I've translated the Java interface into a Python class. The actual implementation of these methods would depend on your specific requirements and use cases.