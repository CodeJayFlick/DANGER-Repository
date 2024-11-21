Here is the translation of the Java code into Python:

```Python
class DefaultGTreeFilterProvider:
    FILTER_STATE = "FILTER_STATE"

    def __init__(self, g_tree):
        self.g_tree = g_tree
        self.filter_factory = GTreeFilterFactory(FilterOptions())
        self.filter_panel = self.create_filter_panel()

    @property
    def filter_component(self):
        return self.filter_panel

    def set_filter_text(self, text):
        self.filter_listener.enable_events(False)
        self.filter_field.set_text(text)
        self.update_model_filter()
        self.filter_listener.enable_events(True)

    def set_enabled(self, enabled):
        self.filter_field.set_enabled(enabled)

    def update_model_filter(self):
        self.g_tree.filter_changed()

    def save_filter_state(self):
        preference_state = PreferenceState()
        preference_state.put_xml_element(FILTER_STATE, self.filter_factory.get_filter_options().to_xml())
        if DockingWindowManager.getInstance(self.g_tree.get_jtree()) is not None:
            docking_window_manager = DockingWindowManager.getInstance(self.g_tree.get_jtree())
            docking_window_manager.put_preference_state(self.preference_key, preference_state)

    def set_filter_options(self, filter_options):
        self.options_set = True
        self.filter_factory = GTreeFilterFactory(filter_options)
        self.save_filter_state()
        self.update_model_filter()

    @property
    def preference_key(self):
        return None

    def load_filter_preference(self, window_manager, unique_preference_key):
        if not self.options_set:
            self.preference_key = unique_preference_key
            if window_manager is None or window_manager.get_preference_state(unique_preference_key) is None:
                return
            xml_element = window_manager.get_preference_state(unique_preference_key).get_xml_element(FILTER_STATE)
            if xml_element is not None:
                filter_options = FilterOptions().restore_from_xml(xml_element)
                self.filter_factory = GTreeFilterFactory(filter_options)
        self.update_model_filter()

    def create_filter_panel(self):
        new_filter_panel = JPanel(BorderLayout())
        new_filter_panel.set_border( BorderFactory.create_bevel_border(BevelBorder.LOWERED) )
        filter_label = JLabel(" Filter: ")
        new_filter_panel.add_component(filter_label, BorderLayout.WEST)

        self.filter_field = JTextField()
        new_filter_panel.add_component(self.filter_field, BorderLayout.CENTER)
        self.filter_field.add_filter_listener(self.filter_listener)

        self.filter_state_button = EmptyBorderButton(self.filter_factory.get_filter_state_icon())
        self.filter_state_button.set_action_listener(lambda e: FilterOptionsEditorDialog(self.filter_factory.get_filter_options()).show_dialog(new_filter_panel))
        new_filter_panel.add_component(self.filter_state_button, BorderLayout.EAST)
        return new_filter_panel

    class FilterDocumentListener:
        def __init__(self):
            self.process_events = True

        def filter_changed(self, text):
            if self.process_events:
                self.update_model_filter()

        def enable_events(self, enabled):
            self.process_events = enabled


class GTreeFilterProvider:
    pass
```

Note: The above Python code is not a direct translation of the Java code. It's more like an equivalent implementation in Python.