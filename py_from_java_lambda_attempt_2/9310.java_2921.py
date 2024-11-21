Here is the translation of the Java code into Python:

```Python
class ActionAdapter:
    def __init__(self, docking_action):
        self.docking_action = docking_action
        self.listeners = []
        self.context_provider = None
        self.default_action = None

    def set_default_action(self, default_action):
        self.default_action = default_action

    def add_listener(self, listener):
        self.listeners.append(listener)

    def get_value(self, key):
        if key == 'NAME':
            return self.docking_action.name()
        elif key == 'SHORT_DESCRIPTION':
            return self.docking_action.description
        elif key == 'LONG_DESCRIPTION':
            return self.docking_action.description
        elif key == 'SMALL_ICON':
            return self.get_icon()
        elif key == 'ACCELERATOR_KEY':
            return self.docking_action.key_binding
        else:
            return None

    def get_icon(self):
        if self.docking_action.toolbar_data is not None:
            return self.docking_action.toolbar_data.icon
        elif self.docking_action.menu_bar_data is not None:
            return self.docking_action.menu_bar_data.menu_icon
        elif self.docking_action.popup_menu_data is not None:
            return self.docking_action.popup_menu_data.menu_icon
        else:
            return None

    def is_enabled(self):
        return self.docking_action.is_enabled()

    def put_value(self, key, value):
        print(f"PutValue key = {key} value = {value}")

    def remove_listener(self, listener):
        if listener in self.listeners:
            self.listeners.remove(listener)

    def set_enabled(self, b):
        self.docking_action.set_enabled(b)

    def action_performed(self, e):
        context = None
        if self.context_provider is not None:
            context = self.context_provider.get_action_context(None)
        elif context is None:
            context = ActionContext()
            context.source_object = e.source
        if self.docking_action.is_enabled_for_context(context):
            self.docking_action.action_performed(context)
        else:
            if self.default_action is not None:
                self.default_action.action_performed(e)

    def property_changed(self, evt):
        for listener in self.listeners:
            listener.property_change(evt)


class ActionContext:
    def __init__(self):
        self.source_object = None

    def set_source_object(self, source_object):
        self.source_object = source_object
```

Please note that Python does not have direct equivalent of Java's `ActionEvent` and `PropertyChangeListener`. So I've replaced them with Python's built-in event handling mechanism.