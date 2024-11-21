Here is the translation of the Java code to Python:
```
import bukkit.entity.player as Player
from typing import Optional

class CursorSlot:
    def __init__(self, player: Player):
        self.player = player

    @property
    def player(self) -> Player:
        return self._player

    def get_item(self) -> Optional[Player]:
        return self.player.get_item_on_cursor()

    def set_item(self, item: Optional[Player]):
        self.player.set_item_on_cursor(item)
        PlayerUtils.update_inventory(self.player)

    def get_amount(self) -> int:
        return self.player.get_item_on_cursor().get_amount()

    def set_amount(self, amount: int):
        self.player.get_item_on_cursor().set_amount(amount)

    def is_same_slot(self, other: 'CursorSlot') -> bool:
        if not isinstance(other, CursorSlot):
            return False
        return self.player.equals(other.player)

    def __str__(self) -> str:
        return f"cursor slot of {PlayerUtils.to_string(self.player)}"
```
Note that I used the `bukkit` module for the player and item classes, as well as the `typing` module to indicate that some variables are optional.