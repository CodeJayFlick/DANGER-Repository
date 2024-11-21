Here is a translation of the Java code into equivalent Python:

```Python
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
```

Please note that this is a direct translation of the Java code into Python, and it may not be exactly equivalent. For example:

- In Java, `@Name`, `@Description`, etc are annotations which don't have direct equivalents in Python.
- The condition checking logic has been simplified for brevity's sake; you might need to adjust this based on your specific requirements.

Also note that the above code assumes that there is a class called `ItemType` and another one called `EnchantmentType`. These classes are not defined here, but they should be implemented according to their respective interfaces.