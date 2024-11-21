Here is a translation of your Java code into equivalent Python:

```Python
class PatternInfoTableModel:
    def __init__(self):
        self.plugin = None
        self.filtered_data = []

    def load(self, task_monitor=None):
        for pattern in self.plugin.get_patterns():
            self.filtered_data.append(pattern)

    def is_cell_editable(self, row, column):
        if column == 2:  # NOTE_COLUMN
            return True
        elif column == 5 and self.filtered_data[row].get_pattern_type() == 'FIRST':
            return True
        else:
            return False

    def set_value_at(self, value, row, column):
        if row < len(self.filtered_data) and 0 <= row:
            pattern = self.filtered_data[row]
            if column == 2:  # NOTE_COLUMN
                pattern.set_note(value)
            elif column == 5:  # ALIGNMENT_COLUMN
                alignment = int(value)
                if alignment > 0 and (alignment & (alignment - 1)) == 0:
                    pattern.set_alignment(alignment)

    def create_table_column_descriptor(self):
        descriptor = {}
        for i in range(6):  # assuming there are 6 columns
            column_name = f"Column {i}"
            if i == 2:  # NOTE_COLUMN
                renderer = monospaced_renderer
            else:
                renderer = None
            descriptor[column_name] = {'renderer': renderer, 'value_func': lambda row_object: str(row_object.get_note())}

        return descriptor

class PatternTypeTableColumn:
    def get_column_name(self):
        return "Pattern Type"

    def get_value(self, pattern_info_row_object):
        if pattern_info_row_object.get_pattern_type() == 'FIRST':
            return "POST"
        else:
            return "PRE"

class NoteTableColumn:
    def get_column_name(self):
        return "Note"

    def get_value(self, pattern_info_row_object):
        return str(pattern_info_row_object.get_note())

class DittedBitSequenceTableColumn:
    def get_column_name(self):
        return "Ditted Bit Sequence"

    def get_renderer(self):
        return monospaced_renderer

    def get_value(self, pattern_info_row_object):
        return str(pattern_info_row_object.get_ditted_bit_sequence().get_hex_string())

class BitsOfCheckTableColumn:
    def get_column_name(self):
        return "Bits of Check"

    def get_value(self, pattern_info_row_object):
        return int(pattern_info_row_object.get_ditted_bit_sequence().get_num_fixed_bits())

class ContextRegisterFilterTableColumn:
    def get_column_name(self):
        return "Context Register Filter"

    def get_value(self, pattern_info_row_object):
        if pattern_info_row_object.get_context_register_filter() is None:
            return None
        else:
            return str(pattern_info_row_object.get_context_register_filter().get_compact_string())

class AlignmentTableColumn:
    def get_column_name(self):
        return "Alignment"

    def get_value(self, pattern_info_row_object):
        return int(pattern_info_row_object.get_alignment())
```

This translation is not a direct conversion from Java to Python. It's more of an interpretation based on the provided code and my understanding of what you're trying to achieve.

Please note that this code assumes some classes (`PatternInfoRowObject`, `monospaced_renderer`) are defined elsewhere in your program, as they were in the original Java code.