class Tool:
    def __init__(self):
        pass

    def get_name(self) -> str:
        raise NotImplementedError("Method not implemented")

    def is_visible(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def set_visible(self, visibility: bool) -> None:
        raise NotImplementedError("Method not implemented")

    def to_front(self) -> None:
        raise NotImplementedError("Method not implemented")

    def get_icon(self) -> 'ImageIcon':
        raise NotImplementedError("Method not implemented")

    def add_component_provider(self, component_provider: 'ComponentProvider', show: bool = False) -> None:
        raise NotImplementedError("Method not implemented")

    def remove_component_provider(self, component_provider: 'ComponentProvider') -> None:
        raise NotImplementedError("Method not implemented")

    def get_component_provider(self, name: str) -> 'ComponentProvider':
        raise NotImplementedError("Method not implemented")

    def set_status_info(self, text: str) -> None:
        raise NotImplementedError("Method not implemented")

    def set_status_info(self, text: str, beep: bool = False) -> None:
        raise NotImplementedError("Method not implemented")

    def clear_status_info(self) -> None:
        raise NotImplementedError("Method not implemented")

    def set_menu_group(self, menu_path: list[str], group: str, menu_subgroup: str) -> None:
        raise NotImplementedError("Method not implemented")

    def add_action(self, action: 'DockingActionIf') -> None:
        raise NotImplementedError("Method not implemented")

    def remove_action(self, action: 'DockingActionIf') -> None:
        raise NotImplementedError("Method not implemented")

    def add_local_action(self, component_provider: 'ComponentProvider', action: 'DockingActionIf') -> None:
        raise NotImplementedError("Method not implemented")

    def remove_local_action(self, component_provider: 'ComponentProvider', action: 'DockingActionIf') -> None:
        raise NotImplementedError("Method not implemented")

    def add_popup_action_provider(self, provider: 'PopupActionProvider') -> None:
        raise NotImplementedError("Method not implemented")

    def remove_popup_action_provider(self, provider: 'PopupActionProvider') -> None:
        raise NotImplementedError("Method not implemented")

    def get_all_actions(self) -> set['DockingActionIf']:
        raise NotImplementedError("Method not implemented")

    def get_docking_actions_by_owner_name(self, owner: str) -> set['DockingActionIf']:
        raise NotImplementedError("Method not implemented")

    def get_active_component_provider(self) -> 'ComponentProvider':
        raise NotImplementedError("Method not implemented")

    def show_component_provider(self, component_provider: 'ComponentProvider', visible: bool = True) -> None:
        raise NotImplementedError("Method not implemented")

    def show_dialog(self, dialog_component: 'DialogComponent') -> None:
        raise NotImplementedError("Method not implemented")

    def get_provider_window(self, component_provider: 'ComponentProvider') -> Window:
        raise NotImplementedError("Method not implemented")

    def to_front(self) -> None:
        raise NotImplementedError("Method not implemented")

    def is_visible(self, component_provider: 'ComponentProvider') -> bool:
        raise NotImplementedError("Method not implemented")

    def is_active(self, component_provider: 'ComponentProvider') -> bool:
        raise NotImplementedError("Method not implemented")

    def update_title(self, component_provider: 'ComponentProvider') -> None:
        raise NotImplementedError("Method not implemented")

    def context_changed(self, provider: 'ComponentProvider' = None) -> None:
        raise NotImplementedError("Method not implemented")

    def add_context_listener(self, listener: 'DockingContextListener') -> None:
        raise NotImplementedError("Method not implemented")

    def remove_context_listener(self, listener: 'DockingContextListener') -> None:
        raise NotImplementedError("Method not implemented")

    def get_window_manager(self) -> 'DockingWindowManager':
        raise NotImplementedError("Method not implemented")

    def get_options(self, category_name: str) -> 'ToolOptions':
        raise NotImplementedError("Method not implemented")

    def set_config_changed(self, changed: bool) -> None:
        raise NotImplementedError("Method not implemented")

    def has_config_changed(self) -> bool:
        raise NotImplementedError("Method not implemented")

    def get_tool_actions(self) -> 'DockingToolActions':
        raise NotImplementedError("Method not implemented")

    def close(self) -> None:
        raise NotImplementedError("Method not implemented")

    def get_default_tool_context(self) -> 'ActionContext':
        raise NotImplementedError("Method not implemented")
