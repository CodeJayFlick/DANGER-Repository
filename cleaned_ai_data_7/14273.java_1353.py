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
