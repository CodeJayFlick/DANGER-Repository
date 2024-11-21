Here is a translation of the Java code into Python:

```Python
class LogTableColumns:
    LEVEL = ("Level", Icon, lambda row: row.icon, SortDirection.ASCENDING, False)
    MESSAGE = ("Message", str, lambda row: row.message, SortDirection.ASCENDING, False)
    ACTIONS = ("Actions", ActionList, lambda row: row.actions, SortDirection.DESCENDING, True)
    TIME = ("Time", datetime.date, lambda row: row.date, SortDirection.DESCENDING, False)

class LogRow:
    def __init__(self, icon, message, date, context, actions):
        self.icon = icon
        self.message = message
        self.date = date
        self.context = context
        self.actions = actions

class LogTableModel(DebouncedRowWrappedEnumeratedColumnTableModel[LogTableColumns]):
    def __init__(self):
        super().__init__("Log", LogTableColumns, lambda row: row.context, lambda row: row)

    def default_sort_order(self) -> List[LogTableColumns]:
        return [LogTableColumns.ACTIONS, LogTableColumns.TIME]

class LogTable(GhidraTable):
    def __init__(self, model):
        super().__init__(model)
```

Please note that this is not a direct translation of the Java code into Python. The above Python code only includes some parts of the original Java code and does not include all classes or methods.