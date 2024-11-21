class ActionToGuiMapper:
    def __init__(self):
        self.global_actions = set()
        self.menu_bar_menu_handler = None
        self.menu_group_map = None
        self.menu_and_toolbar_manager = None
        self.popup_action_manager = None

    @staticmethod
    def set_help_location(c, help_location):
        DockingWindowManager.get_help_service().register_help(c, help_location)

    def add_tool_action(self, action: 'DockingActionIf') -> None:
        if action not in self.global_actions:
            self.global_actions.add(action)
            self.popup_action_manager.add_action(action)
            self.menu_and_toolbar_manager.add_action(action)

    def remove_tool_action(self, action: 'DockingActionIf') -> None:
        self.popup_action_manager.remove_action(action)
        self.menu_and_toolbar_manager.remove_action(action)
        self.global_actions.discard(action)

    @property
    def global_actions(self) -> set:
        return self.global_actions

    def set_active(self, active: bool) -> None:
        if not active:
            self.dismiss_menus()
            DockingWindowManager.clear_mouse_over_help()

    def dismiss_menus(self):
        MenuSelectionManager.default_manager().clear_selected_path()

    def update(self) -> None:
        self.menu_and_toolbar_manager.update()
        self.context_changed_all()

    def dispose(self) -> None:
        self.popup_action_manager.dispose()
        self.menu_and_toolbar_manager.dispose()
        self.global_actions.clear()

    def set_menu_group(self, menu_path: list[str], group: str, menu_subgroup: str) -> None:
        self.menu_group_map.set_menu_group(menu_path, group, menu_subgroup)

    @property
    def menu_handler(self):
        return self.menu_bar_menu_handler

    def context_changed_all(self) -> None:
        self.menu_and_toolbar_manager.context_changed_all()

    def context_changed(self, place_holder: 'ComponentPlaceholder') -> None:
        self.menu_and_toolbar_manager.context_changed(place_holder)

    @property
    def popup_action_manager(self):
        return self.popup_action_manager

    @property
    def menu_group_map(self) -> 'MenuGroupMap':
        return self.menu_group_map

    def show_popup_menu(self, component_info: 'ComponentPlaceholder', popup_context: 'PopupMenuContext') -> None:
        self.popup_action_manager.popup_menu(component_info, popup_context)
