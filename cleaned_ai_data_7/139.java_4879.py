class DisplayFilteredTreeAction:
    def __init__(self, tool, owner, provider):
        super().__init__("DisplayFilteredTree", tool, owner, provider)
        self.is_tree = True
        path = ["Display filtered...", "Tree"]
        self.set_popup_menu_data(path, ObjectTree.ICON_TREE)
        key_binding_data = KeyBindingData(KeyEvent.VK_R,
                                            InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)
        self.set_key_binding_data(key_binding_data)
        help_location = HelpLocation(owner, "display_filtered_tree")
        self.set_help_location(help_location)
        provider.add_local_action(self)

    def do_action(self, container, path):
        clone = ObjectContainer.clone(container)
        clone.set_immutable(True)
        self.get_offspring(clone, path)


# Assuming the following classes exist in Python:
class PluginTool:
    pass

class DebuggerObjectsProvider:
    def add_local_action(self, action):
        pass

class HelpLocation:
    def __init__(self, owner, location):
        self.owner = owner
        self.location = location

class ObjectContainer:
    @classmethod
    def clone(cls, container):
        # Implement this method to create a deep copy of the object.
        return None

    def set_immutable(self, immutable):
        pass

    def get_offspring(self, offspring, path):
        pass


# Assuming the following constants exist in Python:
class InputEvent:
    CTRL_DOWN_MASK = 0
    SHIFT_DOWN_MASK = 1

class KeyEvent:
    VK_R = 0

class ObjectTree:
    ICON_TREE = ""
