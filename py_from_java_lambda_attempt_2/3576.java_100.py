Here is the translation of the given Java code into Python:

```Python
class CycleGroupAction:
    def __init__(self, provider, cycle_group):
        self.cycle_group = cycle_group
        super().__init__(provider, cycle_group.name, "GROUP_NAME", ["Cycle", cycle_group.name], ["Cycle", cycle_group.name], None)
        self.get_popup_menu_data().set_parent_menu_group("GROUP_NAME")
        self.init_key_stroke(cycle_group.default_key_stroke)

    def init_key_stroke(self, key_stroke):
        if key_stroke is None:
            return
        self.set_key_binding_data(KeyBindingData(key_stroke))

    @property
    def cycle_group(self):
        return self._cycle_group

    @cycle_group.setter
    def cycle_group(self, value):
        self._cycle_group = value

    def action_performed(self, context):
        model.cycle_data_type(self.cycle_group)
        request_table_focus()

    def adjust_enablement(self):
        self.enabled = True

    def get_help_name(self):
        return "Cycle"
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements and some other features. Also, the concept of classes in Python is different from those in Java.