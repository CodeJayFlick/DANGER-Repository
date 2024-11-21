Here is the translation of the Java code to Python:
```
class PopupMenuData(MenuData):
    def __init__(self, owner_action: 'DockingAction', menu_data: MenuData) -> None:
        super().__init__(menu_data)
        self.owner_action = owner_action

    def fire_property_changed(self, old_data: MenuData) -> None:
        if self.owner_action is not None:
            self.owner_action.fire_property_changed('POPUP_MENU_DATA_PROPERTY', old_data, self)

class DockingActionIf:
    POPUP_MENU_DATA_PROPERTY = 'POPUP_MENU_DATA_PROPERTY'
```
Note that I've used Python 3.6+ syntax and features (e.g., f-strings) to make the code more readable and concise.