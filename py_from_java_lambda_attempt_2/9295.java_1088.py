Here is the translation of the given Java code into Python:

```Python
class KeyBindingsManager:
    def __init__(self, tool):
        self.tool = tool
        self.docking_key_map = {}
        self.action_to_provider_map = {}

    def add_action(self, provider, action):
        if provider is not None:
            self.action_to_provider_map[action] = provider

        key_binding = action.get_key_binding()
        if key_binding is not None:
            self.add_key_binding(provider, action, key_binding)

    def add_reserved_action(self, action):
        key_binding = action.get_key_binding()
        if ReservedKeyBindings.is_reserved_keystroke(key_binding):
            raise AssertException("Cannot assign action to a reserved keystroke.")

        do_add_key_binding(action.get_provider(), action, key_binding)

    def remove_action(self, action):
        self.action_to_provider_map.pop(action)
        key_binding = action.get_key_binding()
        if key_binding is not None:
            self.remove_key_binding(key_binding, action)

    def add_key_binding(self, provider, action, key_stroke):
        if ReservedKeyBindings.is_reserved_keystroke(key_stroke):
            raise AssertException("Cannot assign action to a reserved keystroke.")

        do_add_key_binding(provider, action, key_stroke)

    def fixup_alt_graph_key_stroke_mapping(self, provider, action, key_stroke):
        modifiers = key_stroke.get_modifiers()
        if (modifiers & InputEvent.ALT_DOWN_MASK) == InputEvent.ALT_DOWN_MASK:
            modifiers |= InputEvent.ALT_GRAPH_DOWN_MASK
            update_key_stroke = KeyStroke(key_stroke.get_code(), modifiers, False)
            do_add_key_binding(provider, action, update_key_stroke)

    def remove_key_binding(self, key_stroke, action):
        if ReservedKeyBindings.is_reserved_keystroke(key_stroke):
            return

        existing_action = self.docking_key_map.get(key_stroke)
        if isinstance(existing_action, MultipleKeyAction):
            multiple_key_action = existing_action
            multiple_key_action.remove_action(action)

    def do_add_key_binding(self, provider, action, key_stroke):
        existing_action = self.docking_key_map.get(key_stroke)
        if existing_action is None:
            self.docking_key_map[key_stroke] = MultipleKeyAction(self.tool, provider, action, key_stroke)
            return

    def add_reserved_key_binding(self, action, key_stroke):
        existing_action = self.docking_key_map.get(key_stroke)
        if existing_action is not None:
            raise AssertException("Attempting to add more than one reserved action to a given keystroke.")

        binding = KeyBindingData.create_reserved_key_binding_data(key_stroke)
        action.set_key_binding_data(binding)
        self.docking_key_map[key_stroke] = ReservedKeyBindingAction(self.tool, action, key_stroke)

    def property_change(self, event):
        name = event.get_property_name()
        action = event.get_source()

        if not name == "KEYBINDING_DATA_PROPERTY":
            return

        old_value = event.get_old_value()
        new_value = event.get_new_value()

        if isinstance(old_value, KeyBindingData) and isinstance(new_value, KeyBindingData):
            key_data = old_value
            if key_data is not None:
                key_stroke = key_data.get_key_binding()
                if key_stroke is not None:
                    self.remove_key_binding(key_stroke, action)

            new_key_data = new_value
            if new_key_data is not None:
                key_stroke = new_key_data.get_key_binding()
                if key_stroke is not None:
                    self.add_key_binding(action_to_provider_map[action], action, key_stroke)

    def get_docking_key_action(self, key_stroke):
        return self.docking_key_map.get(key_stroke)

    def dispose(self):
        self.docking_key_map.clear()
        self.action_to_provider_map.clear()

class MultipleKeyAction:
    def __init__(self, tool, provider, action, key_stroke):
        self.tool = tool
        self.provider = provider
        self.actions = [action]
        self.key_strokes = [key_stroke]

    def add_action(self, provider, action):
        if not isinstance(action, DockingActionIf) or not isinstance(provider, ComponentProvider):
            return

        self.actions.append(action)
        self.provider = provider

    def remove_action(self, action):
        if action in self.actions:
            self.actions.remove(action)

class ReservedKeyBindingAction(MultipleKeyAction):
    pass
```

Please note that Python does not have direct equivalent of Java's `HashMap` and other utility classes. You can use built-in dictionary for similar functionality.