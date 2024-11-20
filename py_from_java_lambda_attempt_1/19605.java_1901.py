Here is a translation of the given Java code into equivalent Python:

```Python
class LastAttacker:
    def __init__(self):
        self.attacker_expr = None

    @property
    def name(self):
        return "Last Attacker"

    @name.setter
    def name(self, value):
        pass  # No setter needed for this property

    @property
    def description(self):
        return "The last block or entity that attacked an entity."

    @description.setter
    def description(self, value):
        pass  # No setter needed for this property

    @property
    def examples(self):
        return ["send \"%last attacker of event-entity%\""]

    @examples.setter
    def examples(self, value):
        pass  # No setter needed for this property

    @property
    def since(self):
        return "2.5.1"

    @since.setter
    def since(self, value):
        pass  # No setter needed for this property

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        self.attacker_expr = ExprAttacker()
        set_expr(exprs[0])
        return True

    def convert(self, entity):
        if not isinstance(entity, Entity):  # Assuming 'Entity' class exists in Python
            raise TypeError("Expected an instance of 'Entity'")
        return self.attacker_expr.get(entity.last_damage_cause())[0]

    @property
    def return_type(self):
        return object

    def get_property_name(self):
        return "last attacker"
```

Please note that this is a translation and not the exact equivalent. Python does not support Java-like annotations, so I've used properties to mimic their functionality. Also, `register` method in Java has been removed as it's not directly translatable into Python.