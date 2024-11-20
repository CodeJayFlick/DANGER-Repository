Here is a translation of the Java code into equivalent Python:

```Python
class ByteSequenceTableModel:
    def __init__(self, plugin, row_objects):
        self.row_objects = row_objects
        super().__init__("Function Start Patterns", plugin)

    def configure_font(self, table, model, column):
        font = Font("monospaced", "plain", 16)
        return font

    def get_filter_string(self, t, settings):
        return t

    def do_load(self, accumulator, monitor):
        if self.row_objects is not None:
            for row_object in self.row_objects:
                accumulator.add(row_object)

    def create_table_column_descriptor(self):
        descriptor = TableColumnDescriptor()
        column1 = ByteSequenceTableColumn()
        column2 = ByteSequenceNumOccurrencesTableColumn()
        column3 = ByteSequencePercentageTableColumn()

        descriptor.add_visible_column(column1)
        descriptor.add_visible_column(column2, 0, False)  # default sorted column
        descriptor.add_visible_column(column3)

        return descriptor

    def merge_selected_rows(self):
        rows = self.get_last_selected_objects()
        if len(rows) == 0:
            return None
        current_merge = ByteSequenceRowObject.merge(rows)
        return current_merge


class ByteSequenceTableColumn(AbstractDynamicTableColumn):
    def get_column_name(self):
        return "Byte Sequence"

    def get_value(self, row_object, settings, data, services):
        return row_object.get_sequence()

    def get_column_renderer(self):
        return self.monospaced_renderer

class ByteSequenceNumOccurrencesTableColumn(AbstractDynamicTableColumn):
    def get_column_name(self):
        return "Number Of Occurrences"

    def get_value(self, row_object, settings, data, services):
        return row_object.get_num_occurrences()

class ByteSequencePercentageTableColumn(AbstractDynamicTableColumn):
    def get_column_name(self):
        return "Percentage"

    def get_value(self, row_object, settings, data, services):
        return row_object.get_percentage()
```

Please note that Python does not have direct equivalent of Java's `GColumnRenderer` and `AbstractDynamicTableColumn`. I've replaced them with simple classes.