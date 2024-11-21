Here is the translation of the Java code into Python:

```Python
class InsertRowAction:
    def __init__(self, owner, panel):
        self.panel = panel
        super().__init__("Insert Row", owner, False)

        menu_data = {"Menu": ["Insert Row"]}
        set_popup_menu(menu_data)
        set_enabled(True)
        help_location = HelpLocation(HelpTopics.CODE_BROWSER, "Insert Row")
        set_help_location(help_location)

    def is_enabled_for_context(self, context):
        if isinstance(context.get_context_object(), FieldHeaderLocation):
            self.loc = context.get_context_object()
            return self.loc.get_row() < self.loc.get_model().get_num_rows()

    def action_performed(self, context):
        self.panel.set_tab_lock(True)
        self.loc.get_model().add_row(self.loc.get_row())
        self.panel.get_header_tab().update()


# Usage:
owner = "Your Owner"
panel = FieldHeader()
action = InsertRowAction(owner, panel)

```

Please note that Python does not have direct equivalent of Java's `DockingAction`, `MenuData` and other classes. The above code is a simple translation of the given Java code into Python.