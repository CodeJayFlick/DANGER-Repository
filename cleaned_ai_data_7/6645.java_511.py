class ClosedPatternTableModel:
    def __init__(self, row_objects):
        self.row_objects = row_objects

    MODEL_NAME = "Closed Patterns"
    MONOSPACE_FONT_SIZE = 16

    monospaced_renderer = None

    def do_load(self, accumulator, monitor):
        if self.row_objects is not None:
            for obj in self.row_objects:
                accumulator.add(obj)

class ClosedPatternTableColumn:
    def __init__(self):
        pass

    @property
    def column_name(self):
        return "Byte Sequence"

    @property
    def renderer(self):
        return self.monospaced_renderer

    def get_value(self, row_object, settings, data, services):
        return str(row_object)

class ClosedPatternNumOccurrencesTableColumn:
    def __init__(self):
        pass

    @property
    def column_name(self):
        return "Number of Occurrences"

    def get_value(self, row_object, settings, data, services):
        return row_object.num_occurrences

class ClosedPatternFixedBitsTableColumn:
    def __init__(self):
        pass

    @property
    def column_name(self):
        return "Fixed Bits"

    def get_value(self, row_object, settings, data, services):
        return row_object.num_fixed_bits

class ClosedPatternPercentageTableColumn:
    def __init__(self):
        pass

    @property
    def column_name(self):
        return "Percentage"

    def get_value(self, row_object, settings, data, services):
        return row_object.percentage


# Usage example:

row_objects = []  # Replace with your actual list of ClosedPatternRowObject instances.
table_model = ClosedPatternTableModel(row_objects)
