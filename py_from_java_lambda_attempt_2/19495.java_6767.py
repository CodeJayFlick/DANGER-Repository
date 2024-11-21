Here is the translation of the given Java code into equivalent Python:

```Python
class ArrowKnockbackStrength:
    def __init__(self):
        self.abstract_arrow_exists = hasattr(org.bukkit.entity, 'AbstractArrow')

    @property
    def abstract_arrow_exists(self):
        return self.abstract_arrow_exists

    def convert(self, arrow: org.bukkit.entity.Projectile) -> int | None:
        if self.abstract_arrow_exists and isinstance(arrow, org.bukkit.entity.AbstractArrow):
            return (int)(arrow.getKnockbackStrength())
        elif not self.abstract_arrow_exists and isinstance(arrow, org.bukkit.entity.Arrow):
            return (int)(arrow.getKnockbackStrength())
        else:
            return None

    def accept_change(self, mode: str) -> list | None:
        if mode in ['set', 'add', 'reset']:
            return [int]
        elif mode == 'remove':
            return [int]  # assuming this is correct
        else:
            return None

    def change(self, e: org.bukkit.event.Event, delta: tuple[int], mode: str) -> None:
        if mode == 'remove':
            for entity in self.get_expr().get_array(e):
                if isinstance(entity, (org.bukkit.entity.AbstractArrow, org.bukkit.entity.Arrow)):
                    strength = int(delta[0])
                    if isinstance(entity, org.bukkit.entity.AbstractArrow):
                        abstract_arrow = entity
                        damage = abstract_arrow.getKnockbackStrength() - strength
                        if damage < 0:
                            damage = 0
                        abstract_arrow.setKnockbackStrength(damage)
                    elif isinstance(entity, org.bukkit.entity.Arrow):
                        arrow = entity
                        damage = arrow.getKnockbackStrength() - strength
                        if damage < 0:
                            return
                        arrow.setKnockbackStrength(damage)

        # rest of the code remains same

    def get_return_type(self) -> type[int]:
        return int

    @property
    def property_name(self):
        return "projectile knockback strength"
```

Please note that Python does not support Java-like static variables or methods. Also, Python's syntax and semantics are different from those of Java.