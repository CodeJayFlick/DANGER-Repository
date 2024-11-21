class SimpleByteSequenceAnalyzerProvider:
    TITLE_INITIAL = "Byte Sequences for "

    def __init__(self, plugin: 'FunctionBitPatternsExplorerPlugin', 
                 path_filter_string: str, context_register_filter: 'ContextRegisterFilter',
                 row_objects: list['ByteSequenceRowObject'], parent_component: object,
                 pattern_type: 'PatternType'):
        super().__init__(TITLE_INITIAL + path_filter_string, plugin, row_objects, parent_component, pattern_type, 
                         context_register_filter, path_filter_string)

    def create_byte_sequence_table(self, f_plugin: 'FunctionBitPatternsExplorerPlugin', 
                                    row_objects: list['ByteSequenceRowObject']) -> object:
        return DisassembledByteSequenceTableModel(plugin=f_plugin, row_objects=row_objects)


class ByteSequenceAnalyzerProvider:
    pass


class ContextRegisterFilter:
    pass


class PatternType:
    pass


class FunctionBitPatternsExplorerPlugin:
    pass


class ByteSequenceRowObject:
    pass


class DisassembledByteSequenceTableModel:
    def __init__(self, plugin: 'FunctionBitPatternsExplorerPlugin', row_objects: list['ByteSequenceRowObject']):
        self.plugin = plugin
        self.row_objects = row_objects

