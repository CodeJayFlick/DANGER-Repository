Here is the translation of the Java code into Python:

```Python
class PatternEvalTableModel:
    def __init__(self, plugin, program, row_objects):
        self.row_objects = row_objects

    def get_address(self, row):
        return self.get_row_object(row).get_matched_address()

    def create_table_column_descriptor(self):
        descriptor = {}
        for column in ["Address", "Match Type", "Postbits", "Totalbits", "Pattern"]:
            if column == "Address":
                renderer = AddressRenderer()
            elif column == "Pattern":
                renderer = PatternStringRenderer()
            else:
                renderer = DefaultRenderer()

            descriptor[column] = {"renderer": renderer}

        return descriptor

    def do_load(self, accumulator):
        for row_object in self.row_objects:
            accumulator.add(row_object)


class MatchTypeColumn:
    def get_column_name(self):
        return "Match Type"

    def get_value(self, row_object):
        return row_object.get_match_type()


class AddressColumn:
    def get_column_name(self):
        return "Address"

    def get_value(self, row_object):
        return row_object.get_matched_address()


class PostBitsColumn:
    def get_column_name(self):
        return "Postbits"

    def get_value(self, row_object):
        return row_object.get_post_bits()


class TotalBitsColumn:
    def get_column_name(self):
        return "Totalbits"

    def get_value(self, row_object):
        return row_object.get_total_bits()


class PatternStringColumn:
    def get_column_name(self):
        return "Pattern"

    def get_renderer(self):
        return monospaced_renderer

    def get_value(self, row_object):
        return row_object.get_pattern_string()
```

Please note that this is a direct translation of the Java code into Python. The original code was written for an IDE (Integrated Development Environment) and might not work as-is in a standard Python environment.