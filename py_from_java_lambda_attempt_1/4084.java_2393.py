Here is the translation of the Java code into Python:

```Python
class NextPrevAddressPlugin:
    HISTORY_MENU_GROUP = "1_Menu_History_Group"
    PREVIOUS_ACTION_NAME = "Previous Location in History"
    NEXT_ACTION_NAME = "Next Location in History"
    CLEAR_MENUPATH = ["Navigation", "Clear History"]

    def __init__(self, tool):
        self.history_service = None
        self.next_action = None
        self.previous_action = None
        self.clear_action = None

        super().__init__()
        self.create_actions()

    @property
    def history_service(self):
        return self._history_service

    @history_service.setter
    def history_service(self, value):
        self._history_service = value

    # ... other properties and methods ...

class NextPreviousAction:
    def __init__(self, name, owner, is_next):
        super().__init__()
        self.is_next = is_next

        set_help_location(HelpTopics.NAVIGATION, name)
        int keycode = is_next and KeyEvent.VK_RIGHT or KeyEvent.VK_LEFT
        set_key_binding_data(KeyBindingData(keycode, InputEvent.ALT_DOWN_MASK))
        description(is_next and "Go to next location" or "Go to previous location")

    def is_enabled_for_context(self, context):
        navigatable = get_navigatable(context)
        if not navigatable:
            return False
        if self.is_next:
            return history_service.has_next(navigatable)
        return history_service.has_previous(navigatable)

    # ... other methods ...

class NavigationAction:
    def __init__(self, location, is_next):
        super().__init__()
        self.location = location
        self.is_next = is_next

        set_help_location(HelpTopics.NAVIGATION, "Navigation_History")
        menu_bar_data(MenuData([build_action_name(location)], navigatable.get_navigatable_icon()))
        enabled(True)

    def action_performed(self, context):
        if self.is_next:
            history_service.next(navigatable, location)
        else:
            history_service.previous(navigatable, location)

# ... other classes and methods ...
```

Please note that this is a direct translation of the Java code into Python.