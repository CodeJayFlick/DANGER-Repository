Here is the translation of the Java code into Python:

```Python
class MenuManager:
    NULL_GROUP_NAME = "<null group>"

    def __init__(self, name: str, mnemonic_key: chr, group: str, use_popup_path: bool, menu_handler, menu_group_map):
        self.name = name
        self.menu_path = [name]
        self.mnemonic_key = mnemonic_key
        self.level = 0
        self.group = group
        self.use_popup_path = use_popup_path
        self.menu_handler = menu_handler
        self.menu_group_map = menu_group_map

    def add_action(self, action: 'DockingActionIf'):
        if not SwingUtilities.isEventDispatchThread():
            raise Exception("Calls to MenuManager must be in the Swing Thread!")
        self.reset_menus()
        if is_sub_menu(action.get_menu_data()):
            sub_menu = self.get_sub_menu(action.get_menu_data())
            sub_menu.add_action(action)
        else:
            self.managed_menu_items.append(MenuItemManager(self.menu_handler, action, use_popup_path=self.use_popup_path))

    def get_submenu(self, menu_data: 'MenuData'):
        full_path = menu_data.get_menu_path()
        display_name = full_path[self.level]
        mnemonic_key = self.get_mnemonic_key(display_name)
        real_name = self.strip_mnemonic_amp(display_name)
        sub_menu = self.sub_menus.get(real_name)
        if sub_menu is not None:
            return sub_menu
        sub_menu_level = self.level + 1
        sub_menu_path = full_path[:sub_menu_level]
        group = self.get_subgroup(menu_data, real_name, sub_menu_path)
        sub_menu = MenuManager(real_name, sub_menu_path, mnemonic_key, sub_menu_level, group, use_popup_path=self.use_popup_path, menu_handler=self.menu_handler, menu_group_map=self.menu_group_map)
        self.sub_menus[real_name] = sub_menu
        self.managed_menu_items.append(sub_menu)
        return sub_menu

    def get_subgroup(self, menu_data: 'MenuData', real_name: str, full_path: list):
        if pull_right_group := menu_data.get_parent_menu_group():
            return pull_right_group
        return real_name

    # ... rest of the class methods ...

class MenuItemManager:
    def __init__(self, menu_handler, action: 'DockingActionIf', use_popup_path: bool):
        self.menu_item = None
        self.action = action
        self.use_popup_path = use_popup_path
        if not SwingUtilities.isEventDispatchThread():
            raise Exception("Calls to MenuManager must be in the Swing Thread!")
        self.reset_menus()

    def get_action(self) -> 'DockingActionIf':
        return self.action

class DockingMenuUI:
    @classmethod
    def create_ui(cls, menu: JMenu):
        # implementation of UI creation
        pass

# ... rest of the class definitions ...
```

Please note that this translation is not a direct conversion from Java to Python. It's more like an interpretation and might require some adjustments based on your specific use case.

Also, please be aware that `JPopupMenu`, `JMenu`, `SwingUtilities` are part of Swing library which is not available in standard Python. You would need to either import the Swing library or implement equivalent functionality using other libraries (like Tkinter) if you want to run this code directly in a Python environment.

Lastly, some methods like `get_menu_data()`, `is_sub_menu()` and others are missing from your original Java code snippet.