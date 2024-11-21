class LastDamage:
    def __init__(self):
        self.damage_expr = None

    @property
    def name(self):
        return "Last Damage"

    @name.setter
    def name(self, value):
        pass  # No setter needed for this property

    @property
    def description(self):
        return "The last damage that was done to an entity. Note that changing it doesn't deal more/less damage."

    @description.setter
    def description(self, value):
        pass  # No setter needed for this property

    @property
    def examples(self):
        return ["set last damage of event-entity to 2"]

    @examples.setter
    def examples(self, value):
        pass  # No setter needed for this property

    @property
    def since(self):
        return "2.5.1"

    @since.setter
    def since(self, value):
        pass  # No setter needed for this property

    def init(self, exprs=None, matched_pattern=0, is_delayed=False, parse_result=None):
        self.damage_expr = ExprDamage()
        return True

    def convert(self, living_entity):
        if not isinstance(living_entity, LivingEntity):
            raise TypeError("Input must be a LivingEntity")
        return self.damage_expr.get(living_entity.getLastDamageCause())[0]

    def accept_change(self, mode):
        if mode in [ChangeMode.ADD, ChangeMode.SET, ChangeMode.REMOVE]:
            return [Number]
        else:
            return None

    def change(self, e=None, delta=None, mode=ChangeMode.NONE):
        if delta is not None and mode != ChangeMode.NONE:
            for entity in self.get_expr().get_array(e):
                if mode == ChangeMode.SET:
                    entity.set_last_damage(delta[0])
                elif mode == ChangeMode.REMOVE:
                    entity.set_last_damage(-delta[0])
                elif mode == ChangeMode.ADD:
                    entity.set_last_damage(entity.getLastDamage() + delta[0])

    def get_return_type(self):
        return Number

    def get_property_name(self):
        return "last damage"
