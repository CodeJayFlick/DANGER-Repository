Here is a translation of the Java code into equivalent Python code:

```Python
import unittest
from ghidra.app.plugin.core.symtable import FilterDialog
from docking.widgets.table.threaded import ThreadedTableModel
from ghidra.app.plugin.core.symtable import SymbolTablePlugin
from ghidra.util.exception import CorruptHostError

class TestSymbolTablePlugin(unittest.TestCase):

    def test_capture_refs_to(self):
        symbol_provider = get_symbol_table_provider()
        show_component_provider(symbol_provider, True)
        move_provider_to_its_own_window(symbol_provider, 940, 642)

        references_provider = show_and_arrange_references_provider(symbol_provider)
        set_reference_type(references_provider, "References To")

        table = get_table(symbol_provider)
        set_column_sizes(table)
        select_row(table, "WideCharToMultiByte")
        trigger_text(table, "\n")  # hack to kick the references table

        window = window_for_component(symbol_provider.get_component())
        capture_window(window)

    def test_capture_instr_from(self):
        symbol_provider = get_symbol_table_provider()
        show_component_provider(symbol_provider, True)
        move_provider_to_its_own_window(symbol_provider, 940, 642)

        references_provider = show_and_arrange_references_provider(symbol_provider)
        set_reference_type(references_provider, "Instruction References From")

        table = get_table(symbol_provider)
        set_column_sizes(table)
        select_row(table, "_malloc00403762")
        trigger_text(table, "\n")  # hack to kick the references table

        window = window_for_component(symbol_provider.get_component())
        capture_window(window)

    def test_capture_data_from(self):
        symbol_provider = get_symbol_table_provider()
        show_component_provider(symbol_provider, True)
        move_provider_to_its_own_window(symbol_provider, 940, 642)

        references_provider = show_and_arrange_references_provider(symbol_provider)
        set_reference_type(references_provider, "Data References From")

        table = get_table(symbol_provider)
        set_column_sizes(table)
        select_row(table, "FUN_004010e0")
        trigger_text(table, "\n")  # hack to kick the references table

        window = window_for_component(symbol_provider.get_component())
        capture_window(window)

    def test_capture_symbol_table(self):
        provider = get_symbol_table_provider()
        show_component_provider(provider, True)
        move_provider_to_its_own_window(provider, 950, 400)
        table = get_table(provider)
        set_column_sizes(table)

        select_row(table, "entry00401e46")
        capture_provider(provider)

    def test_capture_filter(self):
        provider = get_symbol_table_provider()
        show_component_provider(provider, True)
        perform_action("Set Filter", "SymbolTablePlugin", False)
        capture_dialog(FilterDialog)

    def test_capture_filter2(self):
        provider = get_symbol_table_provider()
        show_component_provider(provider, True)
        perform_action("Set Filter", "SymbolTablePlugin", False)
        dialog = waitFor_dialog_component(None, FilterDialog, DEFAULT_WINDOW_TIMEOUT)
        advanced_checkbox = getInstanceField("advancedFilterCheckbox", dialog)

        run_swing(lambda: advanced_checkbox.doClick())
        capture_dialog(dialog)


    def show_and_arrange_references_provider(self, symbol_provider):
        references_provider = get_symbol_table_provider()
        show_component_provider(references_provider, True)
        move_provider_to_its_own_window(references_provider, symbol_provider, WindowPosition.BOTTOM)
        return references_provider

    def set_reference_type(self, references_provider, reference_type):
        plugin = env.get_plugin(SymbolTablePlugin)
        action = get_action(plugin, reference_type)
        perform_action(action, references_provider, True)

        ref_provider = getInstanceField("refProvider", plugin)
        model = getInstanceField("referenceKeyModel", ref_provider)
        waitForTableModel(model)


    def get_table(self, provider):
        symbol_panel = getInstanceField("symbolPanel", provider)
        return getInstanceField("symTable", symbol_panel)


    def set_column_sizes(self, table):
        column_model = table.getColumnModel()
        column_count = column_model.getColumnCount()

        for i in range(column_count):
            column = column_model.getColumn(i)
            header_value = column.getHeaderValue()
            if "Name".equals(header_value):
                column.setPreferredWidth(300)
            elif "Reference Count".equals(header_value):
                column.setPreferredWidth(25)
            elif "Offcut Ref Count".equals(header_value):
                column.setPreferredWidth(25)
            elif "Namespace".equals(header_value):
                column.setPreferredWidth(160)
            elif "Location".equals(header_value):
                column.setPreferredWidth(170)
            elif "Source".equals(header_value):
                column.setPreferredWidth(170)
            elif "Type".equals(header_value):
                column.setPreferredWidth(170)


    def select_row(self, table, row_name):
        # note: these values are rough values found my trial-and-error
        run_swing(lambda: 0)