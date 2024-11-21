Here is a translation of the given Java code into equivalent Python:

```Python
class AmountOfItems:
    def __init__(self):
        self.items = None
        self.invis = None

    @staticmethod
    def register_expression():
        pass  # Equivalent to Skript.registerExpression(ExprAmountOfItems.class, Long.class, ExpressionType.PROPERTY, "[the] (amount|number) of %itemtypes% (in|of) %inventories%")

    def init(self, exprs):
        self.items = exprs[0]
        self.invis = exprs[1]

    def get(self, e):
        r = 0
        types = self.items.get(e)
        for inv in self.invis.get(e).values():
            items_loop: for item in inv:
                if isinstance(item, dict) and 'type' in item and 'amount' in item:
                    type_ = item['type']
                    amount = item['amount']
                    if any(t == type_ for t in types):
                        r += amount
                        continue items_loop

        return [r]

    def get_all(self, e):
        r = 0
        types = self.items.get(e)
        for inv in self.invis.get(e).values():
            items_loop: for item in inv:
                if isinstance(item, dict) and 'type' in item and 'amount' in item:
                    type_ = item['type']
                    amount = item['amount']
                    if any(t == type_ for t in types):
                        r += amount
                        continue items_loop

        return [r]

    def get_return_type(self):
        return int  # Equivalent to Long.class, but Python doesn't have a built-in equivalent of Java's long primitive type. Using the int type instead.

    def is_single(self):
        return True  # Equivalent to boolean isSingle() { return true; }

    def __str__(self, e=None, debug=False):
        if not isinstance(e, dict) or 'event' not in e:
            event = None
        else:
            event = e['event']
        return f"number of {self.items} in {self.invis}"
```

Please note that this is a translation and may require adjustments based on the actual usage.