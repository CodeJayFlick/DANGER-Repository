Here is the translation of the given Java code into Python:

```Python
class AppliedEnchantments:
    def __init__(self):
        self.registered = False

    @staticmethod
    def register():
        if not AppliedEnchantments.registered:
            Skript().register_expression(AppliedEnchantments, EnchantmentType, "applied enchant[ment]s")
            AppliedEnchantments.registered = True

    def init(self):
        return self.parser.is_current_event(EnchantItemEvent) is False

    @staticmethod
    def get(event):
        if isinstance(event, EnchantItemEvent):
            return [(enchantment_type(entry.key(), entry.value())) for entry in event.get_enchants_to_add().items()]
        else:
            Skript.error("The applied enchantments are only usable in an enchant event.", ErrorQuality.SEMANTIC_ERROR)
            return []

    def accept_change(self, mode):
        if mode == ChangeMode.REMOVE_ALL or mode == ChangeMode.RESET:
            return None
        return [EnchantmentType] + [Enchantment]

    @staticmethod
    def change(event, delta, mode):
        enchants = []
        for item in delta:
            if isinstance(item, EnchantmentType):
                enchants.append(item)
            elif isinstance(item, Enchantment):
                enchants.append(EnchantmentType(item))
        event.get_enchants_to_add().clear()
        if mode == ChangeMode.SET:
            pass
        elif mode == ChangeMode.ADD:
            for enchant in enchants:
                event.get_enchants_to_add()[enchant.type] = enchant.level
        elif mode == ChangeMode.REMOVE:
            for enchant in enchants:
                event.get_enchants_to_add().pop(enchant.type, enchant.level)
        elif mode == ChangeMode.DELETE or mode == ChangeMode.RESET:
            pass

    def is_single(self):
        return False

    @staticmethod
    def get_return_type():
        return EnchantmentType

    def __str__(self, event=None, debug=False):
        if event and isinstance(event, EnchantItemEvent):
            return "applied enchantments"
```

Note: This translation assumes that you have the following classes defined in your Python code:

- `Skript`
- `EnchantmentType`
- `EnchantItemEvent`
- `ErrorQuality`
- `ChangeMode`