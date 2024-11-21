import unittest
from gi.repository import Gtk
import threading

class PropertyEditorTest(unittest.TestCase):

    def setUp(self):
        self.dialog = None

    @unittest.skip("This test needs to be implemented")
    def tearDown(self):
        if self.dialog is not None:
            self.dialog.set_visible(False)
            self.dialog.dispose()
        unittest.util.waitForSwing()

    def show_editor(self, options):
        dialog_component = OptionsDialog("Test Properties", "Properties", [options], None)
        editor_dialog = run_swing(lambda: DockingDialog.create_dialog(None, dialog_component, None))
        threading.Thread(target=lambda: editor_dialog.set_visible(True)).start()
        unittest.util.waitForJDialog(None, "Test Properties", 500)
        self.assertIsNotNone("Dialog failed to launch", editor_dialog)
        unittest.util.waitForPostedSwingRunnables()
        unittest.util.waitForOptionsTree(dialog_component)
        return editor_dialog

    def wait_for_options_tree(self, options_dialog):
        panel = getInstanceField("panel", options_dialog)
        tree = (GTree) getInstanceField("gTree", panel)
        self.wait_for_tree(tree)

    def find_paired_component(self, container, label_text):
        box = [None]
        run_swing(lambda: box[0] = do_find_paired_component(container, label_text))
        return box[0]

    def do_find_paired_component(self, container, label_text):
        components = container.get_children()
        for i in range(len(components)):
            if isinstance(components[i], Gtk.Label) and components[i].get_label() == label_text:
                return components[i + 1]
            elif isinstance(components[i], Gtk.Container):
                component = self.do_find_paired_component(components[i], label_text)
                if component is not None:
                    return component
        return None

    def select_text_field(self, field):
        run_swing(lambda: field.select_all(), True)

    @unittest.skip("This test needs to be implemented")
    def test_int(self):
        options = ToolOptions("Test")
        options.register_option("TestInt", int.max_value, None, "Int")

        self.dialog = self.show_editor(options)
        
        editor = self.find_paired_component(self.dialog, "TestInt")
        self.assertIsNotNone("Could not find editor component", editor)
        self.assertIsInstance(editor, Gtk.Entry)
        text_field = (Gtk.Entry) editor
        self.assertEqual(str(int.max_value), text_field.get_text())

        self.select_text_field(text_field)

        trigger_text(text_field, str(int.min_value))

        press_button_by_text(self.dialog, "OK")

        self.assertEqual(int.min_value, options.get_int("TestInt", 0))

    @unittest.skip("This test needs to be implemented")
    def test_long(self):
        # Same as the int test

    @unittest.skip("This test needs to be implemented")
    def test_float(self):
        # Same as the float test

    @unittest.skip("This test needs to be implemented")
    def test_double(self):
        # Same as the double test

    @unittest.skip("This test needs to be implemented")
    def test_string(self):
        options = ToolOptions("Test")
        options.register_option("TestString", "xyz", None, "String")

        self.dialog = self.show_editor(options)

        editor = self.find_paired_component(self.dialog, "TestString")
        self.assertIsNotNone("Could not find editor component", editor)
        self.assertIsInstance(editor, Gtk.Entry)
        text_field = (Gtk.Entry) editor
        self.assertEqual("xyz", text_field.get_text())

        self.select_text_field(text_field)

        trigger_text(text_field, "abc")

        press_button_by_text(self.dialog, "OK")

        self.assertEqual("abc", options.get_string("TestString", None))

    @unittest.skip("This test needs to be implemented")
    def test_string_with_choices(self):
        # Same as the string with choices test

if __name__ == "__main__":
    unittest.main()
