Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import enum

class MenuItem(enum.Enum):
    HOME = 'HOME'
    # Add more menu items as needed...

class MenuStore:
    def __init__(self):
        self._selected = MenuItem.HOME

    def on_action(self, action: dict) -> None:
        if action['type'] == 'MENU_ITEM_SELECTED':
            menu_action = {'menuItem': action['menuAction']['menuItem']}
            self._selected = menu_action['menuItem']
            self.notify_change()

    @property
    def selected(self):
        return self._selected

def notify_change():
    # TO DO: implement notification mechanism here...
    pass
```
Note that I've used Python's built-in `enum` module to define the `MenuItem` enum, and created a simple class-based implementation of the `MenuStore`. The `on_action` method is similar to its Java counterpart, but uses dictionaries instead of objects.