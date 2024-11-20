Here is a translation of the given Java code into equivalent Python:

```Python
import datetime as dt

class Tool:
    def __init__(self):
        self.off_hand = False

    @property
    def tool(self):
        return self._tool

    @tool.setter
    def tool(self, value):
        if isinstance(value, Slot):
            self._tool = value
        else:
            raise TypeError("Expected a Slot object")

class Slot:
    def __init__(self, item_stack=None):
        self.item_stack = item_stack

    def __str__(self):
        return f"Slot with {self.item_stack}"

def get_tool(living_entity: 'LivingEntity', off_hand=False) -> Slot:
    if isinstance(off_hand, bool):
        tool_slot = "off hand" if off_hand else "main"
    elif not off_hand and living_entity.equipment is None:
        return None
    else:
        tool_slot = "off hand"

    if isinstance(living_entity, Player):
        inventory = living_entity.inventory
        if off_hand:
            slot_number = 1
        else:
            slot_number = inventory.get_held_item_slot()
        return InventorySlot(inventory, slot_number)

class LivingEntity:
    def __init__(self):
        self.equipment = None

def get_tool_event(event: 'Event', living_entities) -> Slot:
    if isinstance(event, PlayerItemHeldEvent):
        player_inventory = event.player.inventory
        return InventorySlot(player_inventory, 0)
    elif isinstance(event, (PlayerBucketFillEvent, PlayerBucketEmptyEvent)):
        player_inventory = event.player.inventory
        return InventorySlot(player_inventory, 1)

class Event:
    pass

class SlotExpression(Expression[LivingEntity]):
    def __init__(self):
        self.off_hand = False

    @property
    def tool(self):
        return self._tool

    @tool.setter
    def tool(self, value):
        if isinstance(value, Slot):
            self._tool = value
        else:
            raise TypeError("Expected a Slot object")

class Expression(Expression[LivingEntity]):
    pass

class PlayerItemHeldEvent(Event):
    def __init__(self, player: 'Player'):
        self.player = player

class PlayerBucketFillEvent(Event):
    def __init__(self, player: 'Player'):
        self.player = player

class PlayerBucketEmptyEvent(Event):
    def __init__(self, player: 'Player'):
        self.player = player
```

This Python code is a direct translation of the given Java code. Note that this code does not include any specific functionality related to Skript or Bukkit plugins as they are not directly translatable into pure Python.