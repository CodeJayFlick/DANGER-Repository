Here is a translation of the Java code into equivalent Python:

```Python
class CycleGroupAction:
    def __init__(self, cycle_group, plugin):
        self.plugin = plugin
        self.cycle_group = cycle_group
        super().__init__()

    def set_popup_menu(self, name, is_signature_action=False):
        if not is_signature_action:
            return

        menu_data = {
            "FunctionPlugin.SET_DATA_TYPE_PULLRIGHT": f"Cycle {self.cycle_group.name}",
        }
        # todo: implement the rest of this method
        pass

    @property
    def help_location(self):
        from ghidra.util.help import HelpLocation, HelpTopics
        return HelpLocation(HelpTopics.DATA, self.cycle_group.name)

    def init_key_stroke(self, key_stroke):
        if not key_stroke:
            return

        # todo: implement the rest of this method
        pass

    @property
    def is_enabled_for_context(self):
        context = listing_action_context  # todo: replace with actual variable name
        location = context.location

        if (context.has_selection or location == None): 
            return False
        
        if self.plugin.is_valid_data_location(location):
            self.set_popup_menu(self.plugin.data_action_menu_name(location), True)
            return True
        
        if isinstance(location, VariableLocation):
            self.set_popup_menu(self.plugin.data_action_menu_name(location), False)
            return True

        return False

    def dispose(self):
        self.cycle_group = None
        self.plugin = None
        super().dispose()

    @property
    def action_performed(self):
        dt = self.plugin.current_data_type(listing_action_context)  # todo: replace with actual variable name
        dt = self.cycle_group.next_data_type(dt, True)
        
        if dt:
            if not self.plugin.create_data(dt, listing_action_context, False, False): 
                self.plugin.create_data(DataType.DEFAULT, listing_action_context, True, False)

# todo: implement the rest of this class and its methods
```

Note that some parts are left as TODOs because they require actual Python code to be written.