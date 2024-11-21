import typing as t

class ShowAllComponentsAction:
    def __init__(self, win_mgr: object, info_list: t.List[object], sub_menu_name: str):
        self.info_list = info_list
        super().__init__(win_mgr, "Show All", sub_menu_name)

        group = "Z"
        menu_data = MenuData(["MENU_WINDOW", sub_menu_name, "Show All"], "", group)
        win_mgr.set_menu_group(["MENU_WINDOW", sub_menu_name], "Permanent")
        self.set_help_location("DockingWindows", "Windows_Menu")

    def actionPerformed(self, context: object):
        focus_me = True
        for info in self.info_list:
            if isinstance(info, ComponentPlaceholder):
                win_mgr.show_component(info, True, focus_me, True)
                focus_me = False

class MenuData:
    def __init__(self, menu_items: t.List[str], icon: str, group: str):
        self.menu_items = menu_items
        self.icon = icon
        self.group = group

class ComponentPlaceholder:
    pass  # No equivalent in Python, just a placeholder for now

# Example usage:
win_mgr = object()  # Replace with actual implementation
info_list = [ComponentPlaceholder(), ...]  # Replace with actual data
sub_menu_name = "My Submenu"
action = ShowAllComponentsAction(win_mgr, info_list, sub_menu_name)
