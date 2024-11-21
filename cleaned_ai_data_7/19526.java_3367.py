class ExprCursorSlot:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Cursor Slot"

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return "The item which the player has on their cursor. This slot is always empty if player has no inventories open."

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def examples(self):
        return ["cursor slot of player is dirt", 
                "set cursor slot of player to 64 diamonds"]

    @examples.setter
    def examples(self, value):
        self._examples = value

    @property
    def since(self):
        return "2.2-dev17"

    @since.setter
    def since(self, value):
        self._since = value

    def get_return_type(self):
        return Slot

    def get_property_name(self):
        return "cursor slot"

    def convert(self, player: 'Player') -> Slot:
        return CursorSlot(player)
