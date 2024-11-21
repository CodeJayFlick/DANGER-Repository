Here is the translation of the given Java code into equivalent Python:

```Python
class InstructionTableModel:
    def __init__(self, table_contents_do, col_names):
        self.table_contents_do = table_contents_do
        self.col_names = col_names

    # Register this model as a subscriber to each DO. This ensures that when a DO is updated (eg: masked or unmasked), 
    # this model will be notified and can update its state.
    def register(self):
        for i in range(len(self.table_contents_do)):
            for j in range(len(self.table_contents_do[i])):
                data_obj = self.table_contents_do[i][j]
                data_obj.register(self)

    @property
    def column_class(self, columnIndex):
        return type(InstructionTableDataObject())

    # This is a method provided by the Observer interface and must be implemented. However, we will not be using it 
    # (see InstructionTableObserver for details).
    def update(self, o, arg):
        pass

    # Called whenever an InstructionTableDataObject has changed.
    def notify_changed(self):
        self.fire_table_data_changed()

class DefaultTableModel:
    def __init__(self, table_contents_do, col_names):
        super().__init__()
        self.table_contents_do = table_contents_do
        self.col_names = col_names

    # This is a method provided by the Observer interface and must be implemented. However, we will not be using it 
    # (see InstructionTableObserver for details).
    def update(self, o, arg):
        pass

    # Called whenever an InstructionTableDataObject has changed.
    def notify_changed(self):
        self.fire_table_data_changed()

class Observable:
    def __init__(self):
        super().__init__()

    # This is a method provided by the Observer interface and must be implemented. However, we will not be using it 
    # (see InstructionTableObserver for details).
    def update(self, o, arg):
        pass

# Usage
table_contents_do = [[InstructionTableDataObject() for _ in range(10)] for _ in range(5)]
col_names = ['Column1', 'Column2']
model = InstructionTableModel(table_contents_do, col_names)
```

Please note that Python does not have direct equivalent of Java's Observer pattern. However, you can achieve similar functionality using events or signals in your application.

Also, the `fire_table_data_changed` method is a custom implementation and may vary based on how you are implementing your table model.