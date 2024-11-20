class DisplayAsTreeAction:
    def __init__(self, tool, owner, provider):
        super().__init__("DisplayTree", tool, owner, provider)
        self.is_tree = True
        path = ["Display as...", "Tree"]
        popup_menu_data = {"path": path, "icon": "tree"}
        key_binding_data = {"key_event": "r", "modifier_mask": "ctrl + down"}
        help_location = {"owner": owner, "help_text": "display_as_tree"}

    def do_action(self, container):
        clone = ObjectContainer(container.target_object, container.link_key)
        self.finish_get_offspring(clone)

class PluginTool:
    pass

class DebuggerObjectsProvider:
    def add_local_action(self, action):
        # implement this method
        pass

class ObjectContainer:
    def __init__(self, target_object, link_key):
        self.target_object = target_object
        self.link_key = link_key

    @property
    def get_target_object(self):
        return self.target_object

    @property
    def link_key(self):
        return self.link_key

class ObjectTree:
    ICON_TREE = "tree"

# Usage example:

tool = PluginTool()
owner = "some_owner"
provider = DebuggerObjectsProvider()

action = DisplayAsTreeAction(tool, owner, provider)
