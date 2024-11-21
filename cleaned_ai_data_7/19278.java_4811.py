class CondIsWearing:
    def __init__(self):
        self.entities = None
        self.types = None

    @staticmethod
    def register():
        PropertyCondition.register(CondIsWearing, "wearing %itemtypes%", "livingentities")

    def init(self, vars, matched_pattern, is_delayed, parse_result):
        if len(vars) != 2:
            raise ValueError("Expected two variables")
        self.entities = vars[0]
        self.types = vars[1]
        self.set_negated(matched_pattern == 1)
        return True

    def check(self, e):
        for entity in self.entities.check(e):
            if not isinstance(entity, LivingEntity):
                continue
            equipment = entity.get_equipment()
            if equipment is None:
                return False
            for item_stack in equipment.get_armor_contents():
                if (self.types.is_of_type(item_stack) and not self.types.is_all()) or (not self.types.is_of_type(item_stack) and self.types.is_all()):
                    return not self.types.is_all()
        return self.types.is_all()

    def __str__(self, e=None, debug=False):
        return PropertyCondition.__str__(self, "BE", e, debug, self.entities, f"wearing {self.types}")

class LivingEntity:
    pass

class ItemType:
    def is_of_type(self, item_stack):
        raise NotImplementedError("is_of_type")

    def is_all(self):
        raise NotImplementedError("is_all")
