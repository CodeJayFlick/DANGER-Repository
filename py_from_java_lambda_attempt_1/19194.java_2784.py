Here is the translation of the Java code into Python:

```Python
class DefaultConverters:
    def __init__(self):
        pass

    @staticmethod
    def register_converter(from_type, to_type, converter):
        Converters.register_converter(from_type, to_type, converter)

    @staticmethod
    def convert(from_value, converter):
        return converter.convert(from_value)


# Integer - Long
Converters.register_converter(int, long, lambda x: int(x))

# OfflinePlayer - PlayerInventory
def offline_player_to_inventory(offline_player):
    if not offline_player.is_online():
        return None
    online = offline_player.get_player()
    assert online is not None
    return online.get_inventory()

DefaultConverters.register_converter(OfflinePlayer, PlayerInventory, offline_player_to_inventory)

# OfflinePlayer - Player
def offline_player_to_player(offline_player):
    return offline_player.get_player()

DefaultConverters.register_converter(OfflinePlayer, Player, offline_player_to_player)


# CommandSender - Player
def command_sender_to_player(command_sender):
    if isinstance(command_sender, Player):
        return command_sender
    return None

DefaultConverters.register_converter(CommandSender, Player, command_sender_to_player)

# BlockCommandSender - Block
def block_command_sender_to_block(block_command_sender):
    return block_command_sender.get_block()

DefaultConverters.register_converter(BlockCommandSender, Block, block_command_sender_to_block)


# Entity - Player
def entity_to_player(entity):
    if isinstance(entity, Player):
        return entity
    return None

DefaultConverters.register_converter(Entity, Player, entity_to_player)

# Entity - LivingEntity
def entity_to_living_entity(entity):
    if isinstance(entity, LivingEntity):
        return entity
    return None

DefaultConverters.register_converter(Entity, LivingEntity, entity_to_living_entity)


# Block - Inventory
def block_to_inventory(block):
    state = block.get_state()
    if isinstance(state, InventoryHolder):
        return state.get_inventory()
    return None

DefaultConverters.register_converter(Block, Inventory, block_to_inventory)

# Entity - Inventory
def entity_to_inventory(entity):
    if isinstance(entity, InventoryHolder):
        return entity.get_inventory()
    return None

DefaultConverters.register_converter(Entity, Inventory, entity_to_inventory)


# Block - ItemType
def block_to_item_type(block):
    return ItemType(block)

DefaultConverters.register_converter(Block, ItemType, block_to_item_type)


# Location - Block
def location_to_block(location):
    return location.get_block()

DefaultConverters.register_converter(Location, Block, location_to_block)


# Entity - Location
def entity_to_location(entity):
    return entity.get_location()

DefaultConverters.register_converter(Entity, Location, entity_to_location)

# Experience - XpOrbData
def experience_to_xp_orb_data(experience):
    return XpOrbData(experience.get_xp())

DefaultConverters.register_converter(Experience, XpOrbData, experience_to_xp_orb_data)


# Slot - ItemType
def slot_to_item_type(slot):
    item = slot.get_item()
    if item is None:
        item = ItemStack(Material.AIR, 1)
    return ItemType(item)

DefaultConverters.register_converter(Slot, ItemType, slot_to_item_type)


if Skript.is_running_minecraft(1, 11):
    # EnchantmentOffer - EnchantmentType
    def enchantment_offer_to_enchantment_type(enchantement_offer):
        return EnchantmentType(enchantement_offer.get_enchantment(), enchantement_offer.get_enchantment_level())

    DefaultConverters.register_converter(EnchantmentOffer, EnchantmentType, enchantment_offer_to_enchantment_type)
```

Note that this is a direct translation of the Java code into Python. The original Java code has many comments and annotations which are not necessary in Python as it's more concise language.