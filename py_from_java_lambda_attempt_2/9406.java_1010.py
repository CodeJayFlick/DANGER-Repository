Here is the translation of the Java code into Python:

```Python
class DialogToolbarButton:
    def __init__(self, action: 'DockingActionIf', context_provider):
        super().__init__()
        self.docking_action = action
        self.context_provider = context_provider
        self.set_focusable(False)
        mouse_listener = MouseOverMouseListener()
        self.add_mouse_listener(mouse_listener)
        self.docking_action.add_property_change_listener(self)

    def init_from_action(self, action: 'DockingActionIf'):
        self.docking_action = action
        super().init_from_action(action)

    def doActionPerformed(self, e):
        if isinstance(self.docking_action, ToggleDockingActionIf):
            toggle_action = ToggleDockingActionIf(self.docking_action)
            toggle_action.set_selected(not toggle_action.is_selected())
        self.docking_action.action_performed(self.context_provider.get_action_context(None))

    def doPropertyChange(self, event: 'PropertyChangeEvent'):
        super().do_property_change(event)

        property_name = event.get_property_name()
        if property_name == DockingActionIf.ENABLEMENT_PROPERTY:
            self.set_enabled(bool(event.get_new_value()))
        elif property_name == DockingActionIf.DESCRIPTION_PROPERTY:
            set_tooltip_text(self, self.docking_action)
        elif property_name == DockingActionIf.TOOLBAR_DATA_PROPERTY:
            tool_bar_data = event.get_new_value()
            if tool_bar_data is None:
                icon = None
            else:
                icon = tool_bar_data.get_icon()
            self.set_icon(icon)
        elif property_name == ToggleDockingActionIf.SELECTED_STATE_PROPERTY:
            selected_state = bool(event.get_new_value())
            self.set_selected(selected_state)
        elif property_name == DockingActionIf.KEYBINDING_DATA_PROPERTY:
            set_tooltip_text(self, self.docking_action)

    def is_button_selected(self):
        if isinstance(self.docking_action, ToggleDockingActionIf):
            return (ToggleDockingActionIf(self.docking_action)).is_selected()
        else:
            return False

    @property
    def docking_action(self) -> 'DockingActionIf':
        return self._docking_action

    def set_docking_action(self, value: 'DockingActionIf'):
        self._docking_action = value

    def selected(self):
        if isinstance(self.docking_action, ToggleDockingActionIf):
            (ToggleDockingActionIf(self.docking_action)).set_selected(True)
        else:
            super().selected()

    @property
    def is_selected(self) -> bool:
        if isinstance(self.docking_action, ToggleDockingActionIf):
            return (ToggleDockingActionIf(self.docking_action)).is_selected()
        else:
            return False

    def remove_listeners(self):
        self.docking_action.remove_property_change_listener(self)
        super().remove_listeners()

class MouseOverMouseListener(MouseAdapter):
    def mouse_entered(self, event: 'MouseEvent'):
        DockingWindowManager.set_mouse_over_action(self.docking_action)

    def mouse_exited(self, event: 'MouseEvent'):
        DockingWindowManager.set_mouse_over_action(None)
```

Note that I've used type hints for the method parameters and return types.