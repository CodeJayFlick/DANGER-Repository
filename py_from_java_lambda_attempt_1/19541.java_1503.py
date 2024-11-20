Here is the translation of the given Java code into Python:

```Python
class ExprEnchantingExpCost:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Enchanting Experience Cost"

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return {"The cost of enchanting in an enchant event.", 
                "This is number that was displayed in the enchantment table, not the actual number of levels removed."}

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def examples(self):
        return {"on enchant:", 
                "\tsend \"Cost: %the displayed enchanting cost%\" to player"}

    @examples.setter
    def examples(self, value):
        self._examples = value

    @property
    def events(self):
        return "enchant"

    @events.setter
    def events(self, value):
        self._events = value

    @property
    def since(self):
        return "2.5"

    @since.setter
    def since(self, value):
        self._since = value

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not get_parser().is_current_event(EnchantItemEvent()):
            skript.error("The experience cost of enchanting is only usable in an enchant event.", ErrorQuality.SEMANTIC_ERROR)
            return False
        return True

    def get(self, e):
        return [(long)((e).get_exp_level_cost())]

    def accept_change(self, mode):
        if mode == ChangeMode.RESET or mode == ChangeMode.DELETE or mode == ChangeMode.REMOVE_ALL:
            return None
        return [Number(), Experience()]

    def change(self, event, delta, mode):
        if delta is None:
            return 
        c = delta[0]
        cost = int(c) if isinstance(c, Number) else (c).get_xp()
        e = EnchantItemEvent(event)
        match mode:
            case ChangeMode.SET:
                e.set_exp_level_cost(cost)
                break
            case ChangeMode.ADD:
                add = e.get_exp_level_cost() + cost
                e.set_exp_level_cost(add)
                break
            case ChangeMode.REMOVE:
                subtract = e.get_exp_level_cost() - cost
                e.set_exp_level_cost(subtract)
                break
            case _:
                assert False

    def is_single(self):
        return True

    def get_return_type(self):
        return Long()

    def __str__(self, event=None, debug=False):
        return "the displayed cost of enchanting"
```

Please note that Python does not support Java-like annotations or static initialization blocks. Also, the `@Override` annotation is used in Java to indicate that a method overrides one from its superclass; this concept doesn't exist in Python as it's dynamically typed and doesn't require explicit overriding.

This code also assumes you have defined classes like EnchantItemEvent, ChangeMode, ErrorQuality, Number, Experience.