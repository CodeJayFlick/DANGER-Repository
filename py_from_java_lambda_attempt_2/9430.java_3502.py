Here is the translation of the Java code into Python:

```Python
class ToolBarItemManager:
    def __init__(self, action: 'DockingActionIf', window_manager):
        self._tool_bar_action = action
        self._window_manager = window_manager
        action.add_property_change_listener(self)

    @property
    def group(self) -> str:
        return self._tool_bar_action.get_tool_bar_data().get_group()

    def get_button(self) -> 'JButton':
        if not hasattr(self, '_button'):
            button = self.create_button(self._tool_bar_action)
            button.set_enabled(self._tool_bar_action.is_enabled())
        return getattr(self, '_button')

    def create_button(self, action: 'DockingActionIf') -> 'JButton':
        button = action.create_button()
        button.add_action_listener(self)
        button.add_mouse_listener(self)
        button.set_name(action.get_name())
        DockingToolBarUtils.set_tooltip_text(button, action)
        return button

    @property
    def action(self) -> 'DockingActionIf':
        return self._tool_bar_action

    def dispose(self):
        self._tool_bar_action.remove_property_change_listener(self)
        if hasattr(self, '_button'):
            self._button.remove_action_listener(self)
            delattr(self, '_button')

    def property_changed(self, event: 'PropertyChangeEvent'):
        if not hasattr(self, '_button'):
            return
        name = event.get_property_name()
        if name == 'ENABLEMENT_PROPERTY':
            self._button.set_enabled(event.get_new_value())
        elif name == 'DESCRIPTION_PROPERTY':
            DockingToolBarUtils.set_tooltip_text(self._button, self._tool_bar_action)
        elif name == 'TOOLBAR_DATA_PROPERTY':
            tool_bar_data = event.get_new_value()
            if tool_bar_data is not None:
                icon = tool_bar_data.get_icon()
                self._button.setIcon(icon)
        elif name == 'SELECTED_STATE_PROPERTY':
            selected_state = event.get_new_value()
            self._button.setSelected(selected_state)

    def action_performed(self, event: 'ActionEvent'):
        window_manager.clear_mouse_over_help()
        context = self.get_action_context()

        # this gives the UI some time to repaint before executing the action
        SwingUtilities.invokeLater(lambda: 
            if self._tool_bar_action.is_valid_context(context) and \
               self._tool_bar_action.is_enabled_for_context(context):
                if isinstance(self._tool_bar_action, ToggleDockingActionIf):
                    toggle_action = self._tool_bar_action
                    toggle_action.setSelected(not toggle_action.isSelected())
                self._tool_bar_action.action_performed(context)
            )

    def get_action_context(self) -> 'ActionContext':
        if self._window_manager is not None:
            return self._window_manager.get_action_context(self._tool_bar_action)

        provider = self.get_component_provider()
        context = provider.get_action_context(None)
        action_context = context if context is not None else ActionContext(provider, None)
        return action_context

    def __str__(self) -> str:
        return self._tool_bar_action.name
```

Note that I've used type hints for the method parameters and variables where possible. This can help with code readability and static analysis tools like mypy.