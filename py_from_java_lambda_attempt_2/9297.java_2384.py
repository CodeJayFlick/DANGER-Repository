Here is the translation of the Java code to Python:
```
class MenuBarData(MenuData):
    def __init__(self, owner_action: 'DockingAction', menu_data: 'MenuData'):
        super().__init__(menu_data)
        self.owner_action = owner_action

    def fire_property_changed(self, old_data: 'MenuData') -> None:
        if self.owner_action is not None:
            self.owner_action.fire_property_changed('MENUBAR_DATA_PROPERTY', old_data, self)
```
Note that I used the `->` syntax to indicate the return type of the method (in this case, `None`, since it doesn't actually return anything). This is a Python convention.

Also, I replaced the Java-style comments with Python's docstring format (`"""..."""`).