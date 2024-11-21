Here's your Java code translated into Python:

```Python
class BlockCompat:
    INSTANCE = None
    
    def __init__(self):
        if Skript.is_running_minecraft(1, 13):
            self.INSTANCE = NewBlockCompat()
        else:
            self.INSTANCE = MagicBlockCompat()

    @property
    def setter(self):
        return self.INSTANCE.get_setter()

    def get_block_values(self, block_state: 'org.bukkit.block.BlockState') -> dict or None:
        return self.INSTANCE.get_block_values(block_state)

    def get_block_values(self, block: 'org.bukkit.block.Block') -> dict or None:
        if not isinstance(block, Block):
            raise TypeError("Expected org.bukkit.block.Block")
        return self.get_block_values(block.state)

    def get_block_values(self, stack: 'org.bukkit.inventory.ItemStack') -> dict or None:
        if not isinstance(stack, ItemStack):
            raise TypeError("Expected org.bukkit.inventory.ItemStack")
        return self.INSTANCE.get_block_values(stack)

    @staticmethod
    def falling_block_to_state(entity: 'org.bukkit.entity.FallingBlock') -> 'org.bukkit.block.BlockState':
        # This method is missing in the original Java code. It seems to be a conversion from FallingBlock to BlockState.
        pass

    def get_block_values(self, entity: 'org.bukkit.entity.FallingBlock') -> dict or None:
        return self.get_block_values(self.falling_block_to_state(entity))

    @staticmethod
    def create_block_values(type: int, states: dict) -> dict or None:
        # This method is missing in the original Java code. It seems to be a creation of BlockValues from material and state.
        pass

    def get_setter(self):
        return self.INSTANCE.get_setter()

    @staticmethod
    def is_empty(type: int) -> bool:
        if not isinstance(type, int):
            raise TypeError("Expected integer")
        # This method seems to check whether the given material implies emptiness. On Minecraft 1.13+, there are several blocks that do so.
        pass

    @staticmethod
    def is_liquid(type: int) -> bool:
        if not isinstance(type, int):
            raise TypeError("Expected integer")
        # This method seems to check whether the given material is a liquid.
        pass


class NewBlockCompat(BlockCompat):

    def get_setter(self):
        return BlockSetter()


class MagicBlockCompat(BlockCompat):

    def get_setter(self):
        return BlockSetter()
```

Note: The original Java code had several classes (`NewBlockCompat`, `MagicBlockCompat`) and interfaces that were not provided in the given snippet. I've added them here based on their names, but you might need to adjust or replace these with actual implementations depending on your specific use case.

Also note that Python does not have direct equivalents of Java's static methods, classes, etc., so some adjustments had to be made for translation purposes.