Here is the translation of the given Java code into Python:

```Python
class AbstractSelectionNavigationAction:
    ICON = "Icons.NAVIGATE_ON_INCOMING_EVENT_ICON"
    SELECTED_STATE = "SELECTION_NAVIGATION_SELECTED_STATE"

    def __init__(self, name, owner, table):
        self.table = table
        self.selection_listener = None
        self.is_initialized = False

        super().__init__(name, owner)

        set_tool_bar_data(ToolBarData(self.ICON))
        description = HTMLUtilities.to_html("Toggle on means to navigate to the location in the program that corresponds to the selected row, as the selection changes.")
        help_location = HelpLocation("Search", "Selection_Navigation")
        self.set_description(description)
        self.set_help_location(help_location)

    def set_enabled(self, enable):
        super().set_enabled(enable)

        if enable and self.is_selected():
            table.get_selection_model().add_list_selection_listener(self.selection_listener)
        else:
            table.get_selection_model().remove_list_selection_listener(self.selection_listener)

        save_state()

    def set_selected(self, value):
        super().set_selected(value)

        toggle_selection_listing(value)

    def navigate(self):
        pass

class SelectionListener(list_selection_listener):
    def on_value_changed(self, e):
        if not e.get_value_is_adjusting():
            row_count = table.get_selected_row_count()
            if row_count != 1:
                return
            self.navigate()

def toggle_selection_listing(self, listen):
    if table is None:
        return

    if listen:
        table.get_selection_model().add_list_selection_listener(self.selection_listener)
    else:
        table.get_selection_model().remove_list_selection_listener(self.selection_listener)

    save_state()

class HierarchyListener(list_hierarchy_listener):
    def on_hierarchical_changed(self, e):
        change_flags = e.get_change_flags()
        if displayability_changed == (change_flags & displayability_changed):
            if table.is_displayable():
                restore_state()
                table.remove_hierarchy_listener(self)
```

Note: The above Python code is not a direct translation of the given Java code. It's more like an equivalent implementation in Python, as there are some differences between the two languages that make it difficult to directly translate the code.