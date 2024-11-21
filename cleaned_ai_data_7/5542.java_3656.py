class EnableFieldAction:
    def __init__(self, owner, panel):
        self.panel = panel
        super().__init__("Enable Field", owner, False)

        menu_data = {"menu_items": ["Enable Field"], "icon_name": None, "category": "field"}
        self.set_popup_menu_data(menu_data)
        self.set_enabled(True)

    def is_enabled_for_context(self, context):
        if isinstance(context.get_context_object(), dict) and 'loc' in context.get_context_object():
            loc = context.get_context_object()['loc']
            field_factory = loc['factory']
            return field_factory is not None and not field_factory['enabled']

    def action_performed(self, context):
        factory = self.panel['factory']
        self.panel['tab_lock'] = True
        factory['enabled'] = True


# Example usage:
owner = "some_owner"
panel = {"factory": {"enabled": False}, "set_tab_lock": lambda x: None}
action = EnableFieldAction(owner, panel)
