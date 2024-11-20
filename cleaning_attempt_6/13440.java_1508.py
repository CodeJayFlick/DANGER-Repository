import unittest
from ghidra.app.plugin.core.exporter import ExporterDialog
from ghidra.app.util.options import OptionsDialog
from ghidra.framework.model import *
from ghidra.program.model.listing import Program
from ghidra.app.util.preferences import Preferences

class TestExporterPlugin(unittest.TestCase):

    def test_export_dialog(self):
        # override the user of 'user.home' in the dialog
        Preferences.setProperty("LAST_EXPORT_DIRECTORY", "/path")

        df = create_domain_file()
        dialog = ExporterDialog(tool, df)
        run_swing(lambda: tool.show_dialog(dialog), False)
        wait_for_swing()
        capture_dialog(dialog)

    def test_ascii_options(self):
        perform_action("Export Program", "ExporterPlugin", False)
        d = wait_for_dialog_component(ExporterDialog)
        choose_exporter(d, "Ascii")
        option_dialog = wait_for_dialog_component(OptionsDialog)
        capture_dialog(option_dialog)

    def test_c_options(self):
        perform_action("Export Program", "ExporterPlugin", False)
        d = wait_for_dialog_component(ExporterDialog)
        choose_exporter(d, "C/C++")
        option_dialog = wait_for_dialog_component(OptionsDialog)
        capture_dialog(option_dialog)

    def test_intel_hex_options(self):
        perform_action("Export Program", "ExporterPlugin", False)
        d = wait_for_dialog_component(ExporterDialog)
        choose_exporter(d, "Intel Hex")
        option_dialog = wait_for_dialog_component(OptionsDialog)
        capture_dialog(option_dialog)

    def choose_exporter(self, dialog, format_name):
        exporters_combo = find_component(dialog, JComboBox)
        set_selected_exporter(exporters_combo, format_name)
        press_button_by_text(dialog.get_component(), "Options...", False)

    def set_selected_exporter(self, combo_box, exporter_name):
        run_swing(lambda: 
            for i in range(combo_box.get_item_count()):
                obj = combo_box.get_item_at(i)
                if isinstance(obj, Exporter):
                    exp = Exporter(obj)
                    if exp.name == exporter_name:
                        combo_box.set_selected_item(exp)
                        return
        )

    def create_domain_file(self):
        root = TestDummyDomainFolder(None, "Project")
        df = TestDummyDomainFile(root, "Program_A")
        df.domain_object_class = Program
        return df

if __name__ == "__main__":
    unittest.main()
