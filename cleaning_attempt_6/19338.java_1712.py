class EffEnchant:
    def __init__(self):
        self.item = None
        self.enchs = None

    @staticmethod
    def register_effect():
        Skript.register_effect(EffEnchant, ["enchant %~itemtypes% with %enchantmenttypes%", "disenchant %~itemtypes%"])

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.item = ItemType(exprs[0])
        if not ChangerUtils.accepts_change(self.item, ChangeMode.SET, ItemStack):
            Skript.error(f"{self.item} cannot be changed, thus it cannot be (dis)enchanted")
            return False
        if matched_pattern == 0:
            self.enchs = EnchantmentType(exprs[1])
        return True

    def execute(self, e):
        i = self.item.get_single(e)
        if i is None:
            return
        if self.enchs is not None:
            types = self.enchs.get_array(e)
            for type in types:
                ench = type.get_type()
                assert ench is not None
                i.add_enchantments(EnchantmentType(ench, type.get_level()))
            self.item.change(e, [i], ChangeMode.SET)
        else:
            types = i.get_enchantment_types()
            if types is None:
                return
            for ench in types:
                assert ench is not None
                i.remove_enchantments(ench)
            self.item.change(e, [i], ChangeMode.SET)

    def __str__(self, e=None, debug=False):
        if self.enchs is None:
            return f"disenchant {self.item}"
        else:
            return f"enchant {self.item} with {self.enchs}"

class Skript:
    @staticmethod
    def register_effect(effect_class, patterns):
        pass

    @staticmethod
    def error(message):
        print(f"Error: {message}")

class ChangerUtils:
    @staticmethod
    def accepts_change(item, mode, target_type):
        return True  # Replace this with your actual logic

class ItemType:
    def __init__(self, exprs):
        pass

    def get_single(self, e):
        return None  # Replace this with your actual logic

    def add_enchantments(self, enchants):
        pass

    def remove_enchantments(self, enchantment_type):
        pass

class EnchantmentType:
    def __init__(self, type, level):
        self.type = type
        self.level = level

    @staticmethod
    def get_array(e):
        return []  # Replace this with your actual logic

    def get_type(self):
        return self.type

    def get_level(self):
        return self.level

class Kleenean:
    pass
