class DisassembledByteSequenceTableModel:
    def __init__(self, plugin, row_objects):
        self.row_objects = row_objects

    def do_load(self, accumulator, monitor):
        if self.row_objects is not None:
            for obj in self.row_objects:
                accumulator.add(obj)

    def create_table_column_descriptor(self):
        descriptor = {}
        descriptor['ByteSequenceTableColumn'] = ByteSequenceTableColumn()
        descriptor['ByteSequenceDisassemblyTableColumn'] = ByteSequenceDisassemblyTableColumn()
        descriptor['ByteSequenceNumOccurrencesTableColumn'] = ByteSequenceNumOccurrencesTableColumn(0, False)
        return descriptor

    class ByteSequenceDisassemblyTableColumn:
        def get_column_name(self):
            return "Disassembly"

        def get_value(self, row_object, settings, data, s_provider):
            return row_object.get_disassembly()

        def get_column_renderer(self):
            # monospacedRenderer is not defined in the original Java code
            pass

class ByteSequenceTableColumn:
    pass

class ByteSequenceNumOccurrencesTableColumn:
    def __init__(self, sort_order, default_sorted):
        self.sort_order = sort_order
        self.default_sorted = default_sorted

class ByteSequencePercentageTableColumn:
    pass
