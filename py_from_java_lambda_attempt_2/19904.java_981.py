Here is the translation of the given Java code into Python:

```Python
class BlockInventoryHolder:
    def __init__(self, block_state):
        super().__init__(block_state, False)

    def get_inventory(self):
        return (getattr(block_state, 'get_inventory')).()
```

Please note that this translation assumes you have a `BlockState` class and an `Inventory` class in your Python code. The original Java code seems to be using some sort of Bukkit API for Minecraft, which is not directly applicable to standard Python programming.