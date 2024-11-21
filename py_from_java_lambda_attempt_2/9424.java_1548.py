Here is the translation of the Java code into Python:

```Python
class MenuItemManager:
    def __init__(self, action_handler: 'MenuHandler', docking_action: 'DockingActionIf', use_popup_path: bool):
        self.menu_handler = action_handler
        self.action = docking_action
        self.is_popup = use_popup_path
        self.button_model_change_listener = None
        self.menu_hover_listener = None

    def get_menu_hover_listener(self) -> callable:
        if not self.menu_handler:
            return lambda e: None  # dummy listener
        return MouseAdapter()

    class MouseAdapter:
        def mouse_entered(self, event):
            component = event.get_component()
            if not component.is_enabled():
                self.menu_handler.menu_item_entered(self.action)

        def mouse_exited(self, event):
            component = event.get_component()
            if not component.is_enabled():
                self.menu_handler.menu_item_exited(self.action)

    def get_button_model_change_listener(self) -> callable:
        if not self.menu_handler:
            return lambda e: None  # dummy listener
        return lambda e: \
            is_armed := self.menu_item.is_armed()
            if is_armed:
                self.menu_handler.menu_item_entered(self.action)
            else:
                self.menu_handler.menu_item_exited(self.action)

    def get_group(self) -> str | None:
        menu_data = self.is_popup and self.action.get_popup_menu_data() or self.action.get_menu_bar_data()
        return menu_data and menu_data.get_menu_group()

    def get_subgroup(self) -> str | None:
        menu_data = self.is_popup and self.action.get_popup_menu_data() or self.action.get_menu_bar_data()
        return menu_data and menu_data.get_menu_subgroup()

    def dispose(self):
        if self.action:
            self.action.remove_property_change_listener(self)
        if self.menu_item:
            button_model = self.menu_item.get_model()
            button_model.remove_change_listener(self.button_model_change_listener)
            self.menu_item = None
        self.action = None

    @property
    def menu_item(self) -> JMenuItem | None:
        if not self.menu_item:
            self.menu_item = self.action.create_menu_item(self.is_popup)
            self.menu_item.set_enabled(self.action.is_enabled())
            self.menu_item.add_action_listener(self)
            button_model = self.menu_item.get_model()
            button_model.add_change_listener(self.button_model_change_listener)
            self.menu_item.add_mouse_listener(self.menu_hover_listener)

        return self.menu_item

    @property
    def owner(self) -> str:
        return self.action.get_owner()

    def property_changed(self, event):
        if not self.menu_item:
            return
        name = event.get_property_name()
        if self.is_popup and name == 'popup_menu_data':
            self.update_menu_item()
        elif not self.is_popup and name == 'menu_bar_data':
            self.update_menu_item()
        elif name == 'enablement':
            self.menu_item.set_enabled(event.get_new_value())
            self.menu_item.repaint()
        elif name == 'key_binding_data':
            new_data = event.get_new_value()
            if new_data:
                key_binding = new_data.get_key_binding()
                self.menu_item.set_accelerator(key_binding)
                self.menu_item.revalidate()
        elif name == 'selected_state':
            selected = event.get_new_value()
            self.menu_item.set_selected(selected)
            self.menu_item.revalidate()

    def update_menu_item(self):
        menu_data = self.is_popup and self.action.get_popup_menu_data() or self.action.get_menu_bar_data()
        if menu_data:
            text = menu_data.get_menu_item_name()
            trimmed_text = StringUtilities.trim_middle(text, 50)
            self.menu_item.set_text(trimmed_text)
            icon = menu_data.get_menu_icon()
            mnemonic = menu_data.get_mnemonic()
            self.menu_item.set_icon(icon)
            self.menu_item.set_mnemonic(mnemonic)

    @property
    def action(self) -> 'DockingActionIf':
        return self._action

    def set_action(self, value: 'DockingActionIf'):
        if self.action:
            self.action.remove_property_change_listener(self)
        self._action = value
        if self.action:
            self.action.add_property_change_listener(self)

    @property
    def button_model_change_listener(self) -> callable | None:
        return self._button_model_change_listener

    @button_model_change_listener.setter
    def button_model_change_listener(self, value: callable):
        self._button_model_change_listener = value

    @property
    def menu_hover_listener(self) -> callable | None:
        return self._menu_hover_listener

    @menu_hover_listener.setter
    def menu_hover_listener(self, value: callable):
        self._menu_hover_listener = value

    def action_performed(self, event):
        if not self.menu_handler:
            return
        context = ActionContext()
        context.set_source_object(event.get_source())
        if self.action.is_enabled_for_context(context):
            if isinstance(self.action, ToggleDockingActionIf):
                toggle_action = self.action
                toggle_action.set_selected(not toggle_action.is_selected())
            self.action.performed(context)

    def __str__(self) -> str:
        return self.action.name

    @property
    def menu_item_text(self) -> str | None:
        if not self.menu_handler:
            return None
        menu_data = self.is_popup and self.action.get_popup_menu_data() or self.action.get_menu_bar_data()
        return menu_data and menu_data.get_menu_item_name()

    @property
    def is_empty(self) -> bool:
        return not self.action

    def remove_action(self, action: 'DockingActionIf') -> bool:
        if action == self.action:
            self.dispose()
            return True
        return False
```

Note that I've used Python's type hinting to indicate the types of variables and function parameters. This is optional in Python but can be helpful for code readability and maintainability.

Also, please note that some Java-specific concepts like `MenuHandler`, `DockingActionIf`, `PropertyChangeListener`, etc., have been replaced with their equivalent Python constructs or left as-is if they don't exist in Python (like the `MouseAdapter` class).