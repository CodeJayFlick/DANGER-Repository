Here is the translation of the Java code into Python:

```Python
class GTableToCSV:
    TITLE = "Export to CSV"

    @staticmethod
    def write_csv(file: str, table: object, columns=None) -> None:
        if not isinstance(columns, list):
            columns = []
        
        task = ConvertTask(file, table, columns)
        TaskLauncher(task, table).run()

    @staticmethod
    def write_model(writer: object, table: object, model: object, monitor: object) -> None:
        selected_rows = [int(x) for x in table.get_selected_rows()]
        if not selected_rows:
            GTableToCSV.write_all_model_data(writer, table, model, monitor)
            return
        
        column_count = len(table.get_visible_columns())
        
        for i, row in enumerate(selected_rows):
            if monitor.is_cancelled():
                break
            
            monitor.set_progress(i)
            
            for j in range(column_count):
                column_index = table.convert_column_index_to_view(j)
                value = GTableToCSV.get_cell_value(table, model, row, column_index)
                
                writer.write(f"{value}, ")
            writer.write("\n")

    @staticmethod
    def get_cell_value(table: object, model: object, row: int, column: int) -> str:
        try:
            return table_model_to_text[table].get(table, model).getValueAt(row, 0)
        except Exception as e:
            print(f"Error getting cell value: {e}")
            return ""

    @staticmethod
    def write_all_model_data(writer: object, table: object, model: object, monitor: object) -> None:
        column_count = len(table.get_columns())
        
        for i in range(model.getRowCount()):
            if monitor.is_cancelled():
                break
            
            monitor.set_progress(i)
            
            for j in range(column_count):
                value = GTableToCSV.get_cell_value(table, model, i, j)
                
                writer.write(f"{value}, ")
            writer.write("\n")

    @staticmethod
    def write_column_names(writer: object, columns: list) -> None:
        for column in columns:
            writer.write(f"\"{column.getName()}\", ")

    @staticmethod
    def get_visible_columns_in_order(table: object) -> list:
        return [table.get_column_model().getColumn(i) for i in range(len(table.get_columns()))]

    @staticmethod
    def get_table_columns_by_index(table: object, indices: list) -> list:
        return [table.get_column_model().getColumn(index) for index in indices]


class ConvertTask(Task):
    def __init__(self, file: str, table: object, columns=None) -> None:
        super().__init__(GTableToCSV.TITLE, True, True, True)
        
        self.file = file
        self.table = table
        if not isinstance(columns, list):
            self.columns = []
        else:
            self.columns = columns

    def run(self, monitor: object) -> None:
        try:
            GTableToCSV.write_csv(self.file, self.table, self.columns)
        except Exception as e:
            print(f"Error writing CSV data: {e}")
        
        if hasattr(DockingWindowManager, 'getInstance'):
            manager = DockingWindowManager.getInstance(self.table)
            if manager is not None:
                manager.setStatusText("Finished writing CSV data")


class TaskLauncher(Task):
    def __init__(self, task: object, table: object) -> None:
        super().__init__(GTableToCSV.TITLE, True, True, True)
        
        self.task = task
        self.table = table

    def run(self) -> None:
        try:
            self.task.run()
        except Exception as e:
            print(f"Error running task: {e}")
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect. The original Java code uses Swing components which are not directly available in Python.