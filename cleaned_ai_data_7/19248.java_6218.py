class CondIsEnchanted:
    def __init__(self):
        self.items = None
        self.enchs = None

    @staticmethod
    def register():
        PropertyCondition.register(CondIsEnchanted, "enchanted [with %-enchantmenttype%]", "itemtypes")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) != 2:
            raise ValueError("Expected two expressions")
        self.items = ItemType(exprs[0])
        self.enchs = EnchantmentType(exprs[1]) if exprs[1] else None
        self.set_negated(matched_pattern == 1)
        return True

    def check(self, e):
        if self.enchs:
            for item in self.items.check(e):
                if not self.enchs.check(e, lambda x: x.has_enchantments()):
                    return False
            return not self.is_negated()
        else:
            return all(item.has_enchantments() for item in self.items.check(e))

    def __str__(self, e=None, debug=False):
        es = str(self.enchs) if self.enchs else ""
        return f"enchanted{'' if not es else ' with ' + es}"


class ItemType:
    pass

class EnchantmentType:
    def has_enchantments(self):
        raise NotImplementedError
