Here is a translation of the Java code into equivalent Python code:

```Python
class LocationReferencesPanel:
    def __init__(self, location_references_provider):
        self.location_references_provider = location_references_provider
        self.build_panel()

    def build_panel(self):
        table_model = LocationReferencesTableModel(self.location_references_provider)
        table_panel = GhidraThreadedTablePanel(table_model, 250)
        self.table = table_panel.get_table()
        self.table.set_html_rendering_enabled(True)
        self.table.set_preferred_scrollable_viewport_size((300, 120))
        self.table.set_selection_mode("MULTIPLE_INTERVAL_SELECTION")

    def get_reference_addresses(self):
        return self.table_model.get_reference_addresses()

    def get_table(self):
        return self.table

    def get_selection(self):
        return self.table.get_program_selection()

    def update_model(self):
        self.table_model.reload()

    def reload_model(self):
        self.table_model.full_reload()

    def add_table_model_listener(self, listener):
        self.table_model.add_table_model_listener(listener)

    def is_initialized(self):
        return self.table_model.is_initialized

    def select_row(self, event):
        return self.table.select_row(event)

    def dispose(self):
        self.table.dispose()
```

Note that Python does not have direct equivalents for Java classes like `JPanel`, `BorderLayout`, etc. These are Swing components and do not translate directly to Python.