Here is the translation of the Java code into Python:

```Python
class RecentlyUsedAction:
    DEFAULT_KEY_STROKE = None
    GROUP_NAME = "Z_RECENT"

    def __init__(self, plugin):
        super().__init__("Recently Used", "Recent", ByteDataType(), plugin)
        self.set_help_location(HelpLocation(plugin.name, "Recently_Used"))

    @property
    def default_key_stroke(self):
        return self.DEFAULT_KEY_STROKE

    def init_key_stroke(self, key_stroke):
        if not isinstance(key_stroke, KeyStroke) or key_stroke != self.DEFAULT_KEY_STROKE:
            # user-defined keystroke
            self.set_unvalidated_key_binding_data(KeyBindingData(key_stroke))
        else:
            self.set_key_binding_data(KeyBindingData(key_stroke))

    def is_enabled_for_context(self, context):
        recent_data_type = self.get_recent_data_type()
        if not isinstance(recent_data_type, DataType) or recent_data_type is None:
            return False
        self.data_type = recent_data_type
        enabled = super().is_enabled_for_context(context)
        return enabled

    def is_add_to_popup(self, context):
        location = context.location
        if isinstance(location, FunctionSignatureFieldLocation):
            return True
        elif isinstance(location, VariableLocation):
            return True
        else:
            return False

    @property
    def recent_data_type(self):
        service = self.plugin.get_tool().get_service(DataTypeManagerService)
        if not isinstance(service, DataTypeManagerService) or service is None:
            return None
        return service.recently_used

    def set_popup_menu(self, name, is_signature_action=False):
        dt = self.recent_data_type
        display_name = f"Last Used: {dt.get_display_name() if dt else '<empty>'}"
        self.set_popup_menu_data(MenuData([FunctionPlugin.SET_DATA_TYPE_PULLRIGHT, display_name], self.GROUP_NAME))

class ByteDataType:
    pass

class KeyStroke:
    def __init__(self):
        pass
```

Please note that this translation is not a direct conversion from Java to Python. The code has been modified and adapted for the differences between the two languages.