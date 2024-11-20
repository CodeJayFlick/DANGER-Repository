class AddLabelAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Add Label", plugin.name)
        self.popup_menu_data = {"path": ["Add Label..."], "label": "Label"}
        self.key_binding_data = {"key_stroke": lambda: (0, 76)}  # VK_L

    def is_enabled_for_context(self, context):
        if not context.address.is_external_address:
            return False
        component_path = context.location.component_path
        if component_path and len(component_path) > 0:
            return False
        return not self.plugin.on_variable_reference(context) and \
               not self.plugin.on_symbol(context) and \
               not self.plugin.on_function(context)

    def action_performed(self, context):
        self.plugin.add_label_callback(context)
