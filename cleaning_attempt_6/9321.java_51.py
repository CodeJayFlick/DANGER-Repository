class ActionToGuiHelper:
    def __init__(self, window_manager):
        self.window_manager = window_manager

    def add_tool_action(self, action: 'DockingActionIf') -> None:
        self.window_manager.add_tool_action(action)

    def remove_tool_action(self, action: 'DockingActionIf') -> None:
        self.window_manager.remove_tool_action(action)

    def add_local_action(self, provider: object, action: 'DockingActionIf') -> None:
        self.window_manager.add_local_action(provider, action)

    def get_component_actions(self, provider: object) -> iter['DockingActionIf']:
        return self.window_manager.get_component_actions(provider)

    def remove_provider_action(self, provider: object, action: 'DockingActionIf') -> None:
        self.window_manager.remove_provider_action(provider, action)

    def key_bindings_changed(self) -> None:
        self.window_manager.schedule_update()
