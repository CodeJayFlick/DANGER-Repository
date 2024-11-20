Here is a translation of the Java code into equivalent Python code:

```Python
class DataAction:
    def __init__(self, name: str, group: str, data_type: object, plugin: object):
        self.group = group
        self.plugin = plugin
        self.data_type = data_type
        super().__init__(name)

    @property
    def help_location(self) -> tuple:
        return (plugin.name, "DataType")

    def set_popup_menu_name(self, name: str, is_signature_action: bool):
        if not is_signature_action:
            menu_data = MenuData([FunctionPlugin.SET_DATA_TYPE_PULLRIGHT, self.data_type.get_display_name()], self.group)
        else:
            menu_data = None
        return menu_data

    @property
    def key_stroke(self) -> tuple:
        return (None,)  # we have no default, but our subclasses may

    def init_key_stroke(self, key_stroke: object):
        if not isinstance(key_stroke, type(None)):
            self.key_binding_data = KeyBindingData(key_stroke)

    @property
    def is_enabled_for_context(self) -> bool:
        context = listing_action_context  # assuming this variable exists in the scope of DataAction class

        if (context.has_selection() or not isinstance(context.get_address(), type(None))):
            return False
        location = context.location()
        if self.plugin.is_valid_data_location(location):
            menu_name = self.plugin.data_action_menu_name(location)
            is_signature_action = True  # assuming this variable exists in the scope of DataAction class
            set_popup_menu_name(menu_name, is_signature_action)  # call to your own method
            return True

        if isinstance(location, VariableLocation):  # assuming this type exists in Python
            menu_name = self.plugin.data_action_menu_name(location)
            is_signature_action = False  # assuming this variable exists in the scope of DataAction class
            set_popup_menu_name(menu_name, is_signature_action)  # call to your own method
            return True

        return False

    def action_performed(self):
        plugin.create_data(data_type, listing_action_context, True)
```

Note that Python does not have direct equivalent for Java's "extends" keyword. Instead, you would use inheritance (i.e., create a subclass of another class).