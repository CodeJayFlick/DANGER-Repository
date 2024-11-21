Here is the translation of the Java code into Python:

```Python
import math

class HealthUtils:
    def get_health(self, e):
        if e.is_dead():
            return 0
        return e.get_health() / 2

    def set_health(self, e, health):
        e.set_health(math.floor(0 + (health * 2)))

    def get_max_health(self, e):
        attribute_instance = ((e).get_attribute("GENERIC_MAX_HEALTH"))
        assert attribute_instance is not None
        return attribute_instance.get_value() / 2

    def set_max_health(self, e, health):
        attribute_instance = ((e).get_attribute("GENERIC_MAX_HEALTH"))
        assert attribute_instance is not None
        attribute_instance.set_base_value(health * 2)

    @staticmethod
    def damage(e, d):
        if d < 0:
            HealthUtils.heal(e, -d)
            return
        e.damage(d * 2)

    @staticmethod
    def heal(e, h):
        if h < 0:
            HealthUtils.damage(e, -h)
            return
        HealthUtils.set_health(e, (HealthUtils.get_health(e) + h))

    @staticmethod
    def get_damage(event):
        return event.get_damage() / 2

    @staticmethod
    def get_final_damage(event):
        return event.get_final_damage() / 2

    @staticmethod
    def set_damage(event, damage):
        event.set_damage(damage * 2)

    @staticmethod
    def set_damage_cause(e, cause):
        e.set_last_damage_cause(EntityDamageEvent(e, cause, 0))

class EntityDamageEvent:
    def __init__(self, entity, cause, damage):
        self.entity = entity
        self.cause = cause
        self.damage = damage

    @property
    def get_damage(self):
        return self.damage

    @property
    def get_final_damage(self):
        return self.damage

    def set_damage(self, damage):
        self.damage = damage

class Damageable:
    def is_dead(self):
        pass  # Implement this method in your subclass

    def get_health(self):
        pass  # Implement this method in your subclass

    def set_health(self, health):
        pass  # Implement this method in your subclass

    def damage(self, d):
        pass  # Implement this method in your subclass
```

Note that I've used the `math` module for floor function and also created a new class called `EntityDamageEvent`, as it seems to be missing from the original Java code.