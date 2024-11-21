Here's your Java code translated into Python:

```Python
class DirectoryTableModel:
    def __init__(self, chooser):
        self.chooser = chooser
        self.files = []

    def insert(self, file):
        self.files.append(file)
        self.fire_table_rows_inserted(len(self.files) - 1, len(self.files) - 1)

    def set_files(self, files_list):
        self.files = list(files_list)
        self.fire_table_data_changed()

    def get_file(self, row):
        if 0 <= row < len(self.files):
            return self.files[row]
        else:
            return None

    def set_file(self, row, file):
        if 0 <= row < len(self.files):
            self.files[row] = file
            self.fire_table_rows_updated(row, row)

    @property
    def name(self):
        return "Directory"

    @property
    def get_row_count(self):
        return len(self.files) if self.files else 0

    def is_cell_editable(self, row, column):
        return False

    @property
    def get_column_count(self):
        return 3

    def get_column_class(self, column_index):
        classes = {
            0: File,
            1: int,
            2: datetime.date
        }
        if column_index in classes:
            return classes[column_index]
        else:
            return str

    def get_column_name(self, column_index):
        names = ["Filename", "Size", "Modified"]
        if 0 <= column_index < len(names):
            return names[column_index]
        else:
            return "<<unknown>>"

    def get_column_value_for_row(self, file, column_index):
        values = {
            0: lambda f: f,
            1: lambda f: f.size() if not self.chooser.get_model().is_directory(f) else f.length(),
            2: lambda f: datetime.date.fromtimestamp(f.last_modified())
        }
        if column_index in values:
            return values[column_index](file)
        else:
            return None

    def get_model_data(self):
        return [File](*self.files)

    @property
    def sort_comparator(self, column_index):
        comparators = {
            0: lambda f1, f2: (f1.name > f2.name) - (f1.name < f2.name),
            1: lambda f1, f2: int(f1.size()) - int(f2.size()),
            2: lambda f1, f2: datetime.date.fromtimestamp(f1.last_modified()).toordinal() - datetime.date.fromtimestamp(f2.last_modified()).toordinal()
        }
        if column_index in comparators:
            return functools.cmp_to_key(comparators[column_index])
        else:
            return super().create_sort_comparator(column_index)

    def is_sortable(self, column_index):
        return True
```

Please note that this code does not include the `fire_table_rows_inserted`, `fire_table_data_changed`, and `fire_table_rows_updated` methods. These are part of Java's Swing framework and do not have direct equivalents in Python.