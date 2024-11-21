Here is the translation of the Java code to Python:
```
import ghidra_framework as gf
from ghidra_util import *
from javax.swing.table import *

class VTMatchDestinationTableProvider:
    def __init__(self, tool: 'gf.PluginTool', controller: 'VTController',
                 sub_tool_manager: 'VTSubToolManager'):
        super().__init__(tool, controller, sub_tool_manager, False)

    def get_matches_table_model(self) -> 'VTMatchOneToManyTableModel':
        if self.one_to_many_table_model is None:
            self.one_to_many_table_model = VTMatchDestinationTableModel(controller)
        return self.one_to_many_table_model

    def initialize_matches_table(self) -> 'GhidraTable':
        table = super().initialize_matches_table()
        # setup the renderers
        column_model = table.columnModel
        source_label_column_index = self.one_to_many_table_model.get_column_index(SourceLabelTableColumn)
        source_label_column = column_model.getColumn(source_label_column_index)
        source_label_column.setCellRenderer(VTSymbolRenderer(controller.get_service_provider(), table))
        return table

class VTMatchDestinationTableModel:
    def __init__(self, controller: 'VTController'):
        # initialize the model here
        pass

class VTSymbolRenderer:
    def __init__(self, service_provider: object, table: 'GhidraTable'):
        self.service_provider = service_provider
        self.table = table

# usage example
tool = gf.PluginTool()
controller = VTController()
sub_tool_manager = VTSubToolManager()

provider = VTMatchDestinationTableProvider(tool, controller, sub_tool_manager)
table_model = provider.get_matches_table_model()
table = provider.initialize_matches_table()
```
Note that I've used the `ghidra_framework` and `ghidra_util` modules as placeholders for the actual Ghidra framework and utility libraries. You will need to replace these with the actual Python bindings for Ghidra.

Also, some Java-specific concepts like interfaces and abstract classes have been replaced with their equivalent Python constructs (e.g., classes without explicit inheritance).