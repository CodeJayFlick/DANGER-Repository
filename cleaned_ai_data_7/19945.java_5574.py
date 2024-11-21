class InventorySlot:
    def __init__(self, invi: 'Inventory', index: int):
        assert invi is not None
        assert index >= 0
        self.invi = invi
        self.index = index

    @property
    def inventory(self) -> 'Inventory':
        return self.invi

    @property
    def index_(self) -> int:
        return self.index

    def get_item(self):
        if self.index == -999:  # Non-existent slot, e.g. Outside GUI 
            return None
        item = self.invi.get_item(self.index)
        return item.clone() if item is not None else ItemStack(Material.AIR, 1)

    def set_item(self, item: 'ItemStack'):
        self.invi.set_item(self.index, item if item.type != Material.AIR else None)
        if isinstance(self.invi, PlayerInventory):
            PlayerUtils.update_inventory((Player) self.invi.get_holder())

    @property
    def amount(self) -> int:
        item = self.invi.get_item(self.index)
        return 0 if item is None else item.amount

    def set_amount(self, amount: int):
        item = self.invi.get_item(self.index)
        if item is not None:
            item.set_amount(amount)
        if isinstance(self.invi, PlayerInventory):
            PlayerUtils.update_inventory((Player) self.invi.get_holder())

    def __str__(self, e=None, debug=False):
        holder = self.invi.get_holder() if self.invi else None
        if holder is not None:
            return f"inventory slot {self.index} of {holder}" if isinstance(self.invi, CraftingInventory) else "crafting slot {} of {}".format(self.index, Classes().to_string(holder))
        return f"inventory slot {self.index} of {Classes().to_string(self.invi)}"
