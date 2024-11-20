Here is a translation of the Java code into equivalent Python:

```Python
class DisplayAsTableAction:
    def __init__(self, tool, owner, provider):
        super().__init__("DisplayTable", tool, owner, provider)
        self.path = ["Display as...", "Table"]
        self.set_popup_menu_data(self.path, "ObjectTable.ICON_TABLE")
        self.set_key_binding_data("VK_T", "CTRL_DOWN_MASK")
        self.help_location = HelpLocation(owner, "display_as_table")
        provider.add_local_action(self)

    def do_action(self, container):
        clone = ObjectContainer.clone(container)
        finish_get_offspring(clone)


class KeyBindingData:
    def __init__(self, key_event, input_mask):
        self.key_event = key_event
        self.input_mask = input_mask


class MenuData:
    def __init__(self, path, icon):
        self.path = path
        self.icon = icon


class HelpLocation:
    def __init__(self, owner, help_text):
        self.owner = owner
        self.help_text = help_text


# Example usage:

tool = "Ghidra"
owner = "DebuggerObjectsProvider"
provider = DebuggerObjectsProvider()
action = DisplayAsTableAction(tool, owner, provider)
```

Please note that Python does not have direct equivalents for Java classes like `docking.action.KeyBindingData`, `ghidra.app.plugin.core.debug.gui.objects.components.ObjectTable` and others. The above code is a simplified translation of the original Java code into equivalent Python syntax.