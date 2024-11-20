Here is a translation of the Java code into equivalent Python:

```Python
class FinalDamage:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        return {
            "name": "Final Damage",
            "description": "How much damage is done in a damage event, considering all types of damage reduction. Can NOT be changed.",
            "examples": ["send \"%final damage%\" to victim"],
            "since": "2.2-dev19",
            "events": ["damage"]
        }

    def init(self):
        if not Skript.is_current_event(EntityDamageEvent):
            Skript.error("The expression 'final damage' can only be used in damage events", ErrorQuality.SEMANTIC_ERROR)
            return False
        return True

    @staticmethod
    def get(event):
        if isinstance(event, EntityDamageEvent):
            return [HealthUtils.get_final_damage(event)]
        else:
            return []

    def accept_change(self, mode):
        Skript.error("Final damage cannot be changed; try changing the 'damage'")
        return None

    def is_single(self):
        return True

    @staticmethod
    def get_return_type():
        return Number

    def __str__(self):
        return "the final damage"
```

Please note that Python does not have direct equivalent of Java's static blocks, annotations or classes with generic types.