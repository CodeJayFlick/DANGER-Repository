Here is the translation of the given Java code into Python:

```Python
class DuplicateMultipleAction:
    ICON = None  # This will be set later when you load your image resource.
    ACTION_NAME = "Duplicate Multiple of Component"
    GROUP_NAME = "COMPONENT_ACTION_GROUP"
    DESCRIPTION = "Duplicate multiple of the selected component"

    def __init__(self, provider):
        self.provider = provider
        self.model = None  # This will be set later when you initialize your model.

    def actionPerformed(self, context):
        indices = self.model.getSelectedComponentRows()
        if len(indices) != 1:
            return

        row = indices[0]
        min_duplicates = 1
        max_duplicates = self.model.getMaxDuplicates(row)
        initial_count = self.model.getLastNumDuplicates()

        number_input_dialog = NumberInputDialog("duplicates", (initial_count > 0) or 1, min_duplicates, max_duplicates)

        help_anchor = f"{self.provider.getHelpName()}_{help_name}_Duplicates_NumberInputDialog"
        help_location = HelpLocation(self.provider.getHelpTopic(), help_anchor)
        number_input_dialog.set_help_location(help_location)

        if number_input_dialog.show():
            count = number_input_dialog.getValue()
            TaskLauncher.launchModal("Duplicating Component", self.do_insert, row, count)
        else:
            request_table_focus()

    def do_insert(self, row, count):
        try:
            self.model.duplicate_multiple(row, count)
        except CancelledException as e:
            # User cancelled
            pass
        except UsrException as e:
            self.model.set_status(str(e), True)

        self.model.fire_table_data_changed()

    def adjust_enablement(self):
        if hasattr(self.model, 'is_duplicate_allowed'):
            self.enabled = self.model.is_duplicate_allowed()
```

Note that this is a direct translation of the Java code into Python. However, there are some differences between the two languages:

1. In Python, we don't need to declare variables before using them.
2. The `@Override` annotation in Java does not exist in Python. Instead, you can simply define your method with the same name and parameters as the original method.
3. There is no direct equivalent of Java's `KeyStroke.getKeyStroke(KeyEvent.VK_M, InputEvent.ALT_DOWN_MASK)` in Python. You would need to use a different library or framework that supports keyboard shortcuts if needed.

Also note that this code assumes you have defined classes like `CompositeEditorTableAction`, `NumberInputDialog`, and `HelpLocation` elsewhere in your program.