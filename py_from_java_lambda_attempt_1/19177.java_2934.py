Here's your Java code translated into Python:

```Python
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from org.bukkit import Material, ItemStack

class ItemUtils:
    def __init__(self):
        pass  # Not to be instanced

    damage_meta = None

    @staticmethod
    def get_damage(stack: ItemStack) -> int:
        if stack.get_item_meta() is not None and isinstance(stack.get_item_meta(), Damageable):
            return (stack.get_item_meta()).get_damage()
        else:
            return 0  # Not damageable item

    @staticmethod
    def set_damage(stack: ItemStack, damage: int) -> None:
        if stack.get_item_meta() is not None and isinstance(stack.get_item_meta(), Damageable):
            (stack.get_item_meta()).set_damage(damage)
            stack.set_item_meta(stack.get_item_meta())
        else:
            stack.set_durability((short)(damage))

    bed_item = None
    bed_block = None

    @staticmethod
    def as_block(type: Material) -> Material | None:
        if type.is_block():
            return type
        elif ItemUtils.damage_meta and (type == ItemUtils.bed_item or type == ItemUtils.bed_block):
            return ItemUtils.bed_block if type == ItemUtils.bed_item else ItemUtils.bed_item
        else:
            return None

    @staticmethod
    def as_item(type: Material) -> Material | None:
        if ItemUtils.damage_meta and (type == ItemUtils.bed_block or type == ItemUtils.bed_item):
            return ItemUtils.bed_item if type == ItemUtils.bed_block else ItemUtils.bed_block
        elif not ItemUtils.damage_meta and type.is_block():
            return ItemUtils.as_block(type)
        else:
            return type

    @staticmethod
    def item_stacks_equal(is1: ItemStack | None, is2: ItemStack | None) -> bool:
        if is1 is None or is2 is None:
            return is1 == is2
        elif is1.get_type() != is2.get_type():
            return False
        else:
            damage = ItemUtils.get_damage(is1)
            return (is1.get_item_meta().equals(is2.get_item_meta()) and damage == ItemUtils.get_damage(is2))
```

Note that I've used the `org.bukkit` module, which you'll need to install separately.