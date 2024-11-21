Here is a translation of the given Java code into equivalent Python:

```Python
class EnderChest:
    def __init__(self):
        pass
    
    @property
    def description(self):
        return "The ender chest of a player."
    
    @property
    def examples(self):
        return ["open the player's ender chest to the player"]
    
    @property
    def since(self):
        return "2.0"
    
    @property
    def name(self):
        return "Ender Chest"

class Player:
    def __init__(self, inventory=None):
        self.inventory = inventory
    
    def get_ender_chest(self):
        return self.inventory

def convert(player: 'Player') -> 'Inventory':
    return player.get_ender_chest()

# This is equivalent to the Java static block
EnderChest.register("enders", "players")

class Inventory:
    pass
```

Please note that Python does not have direct equivalents for some of the Java features used in this code, such as annotations (`@Name`, `@Description`, etc.) or generics.