class EnchantmentUtils:
    def __init__(self):
        self.enchantments = {}
        if Skript.is_running_minecraft(1, 9):
            self.enchantments["protection"] = "PROTECTION_ENVIRONMENTAL"
            self.enchantments["fire_protection"] = "PROTECTION_FIRE"
            self.enchantments["feather_falling"] = "PROTECTION_FALL"
            self.enchantments["blast_protection"] = "PROTECTION_EXPLOSIONS"
            self.enchantments["projectile_protection"] = "PROTECTION_PROJECTILE"
            self.enchantments["respiration"] = "OXYGEN"
            self.enchantments["aqua_affinity"] = "WATER_WORKER"
            self.enchantments["thorns"] = "THORNS"
            self.enchantments["depth_strider"] = "DEPTH_STRIDER"
            self.enchantments["sharpness"] = "DAMAGE_ALL"
            self.enchantments["smite"] = "DAMAGE_UNDEAD"
            self.enchantments["bane_of_arthropods"] = "DAMAGE_ARTHROPODS"
            self.enchantments["knockback"] = "KNOCKBACK"
            self.enchantments["fire_aspect"] = "FIRE_ASPECT"
            self.enchantments["looting"] = "LOOT_BONUS_MOBS"
            self.enchantments["efficiency"] = "DIG_SPEED"
            self.enchantments["silk_touch"] = "SILK_TOUCH"
            self.enchantments["unbreaking"] = "DURABILITY"
            self.enchantments["fortune"] = "LOOT_BONUS_BLOCKS"
            self.enchantments["power"] = "ARROW_DAMAGE"
            self.enchantments["punch"] = "ARROW_KNOCKBACK"
            self.enchantments["flame"] = "ARROW_FIRE"
            self.enchantments["infinity"] = "ARROW_INFINITE"
            self.enchantments["luck_of_the_sea"] = "LUCK"

        if Skript.is_running_minecraft(1, 11):
            self.enchantments["frost_walker"] = "FROST_WALKER"
            self.enchantments["mending"] = "MENDING"

        if Skript.is_running_minecraft(1, 12):
            self.enchantments["binding_curse"] = "BINDING_CURSE"
            self.enchantments["vanishing_curse"] = "VANISHING_CURSE"
            self.enchantments["sweeping_edge"] = "SWEEPING_EDGE"

    def get_key(self, ench):
        if hasattr(ench, 'get_key'):
            return ench.get_key().getKey()
        name = self.enchantments.get(ench)
        assert name is not None, f"missing name for {ench}"
        return name

    @staticmethod
    def by_key(key):
        if Skript.is_running_minecraft(1, 9) and hasattr(Enchantment, 'get_by_key'):
            return Enchantment.getByKey(NamespacedKey.minecraft(key))
        return self.enchantments.inverse().get(key)
