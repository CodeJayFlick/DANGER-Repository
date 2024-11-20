class EffHealth:
    def __init__(self):
        self.damageables = None
        self.damage = None
        self.heal = False

    @staticmethod
    def register_effect():
        Skript.register_effect(EffHealth, "damage %livingentities/itemtypes% by %number% [heart[s]] [with fake cause %-damagecause%]",
                              "heal %livingentities% [by %-number% [heart[s]]]", 
                              "repair %itemtypes% [by %-number%]")

    def init(self, exprs, matched_pattern):
        if matched_pattern == 0 and exprs[2] is not None:
            Skript.warning("The fake damage cause extension of this effect has no functionality, "
                           "and will be removed in the future")
        
        self.damageables = exprs[0]
        if not isinstance(self.damageables.getReturnType(), LivingEntity):
            if not ChangerUtils.accepts_change(self.damageables, ChangeMode.SET, ItemType()):
                Skript.error(f"{self.damageables} cannot be changed, thus it cannot be damaged or repaired.")
                return False
        self.damage = exprs[1]
        self.heal = matched_pattern >= 1

        return True

    def execute(self):
        damage = 0.0
        if self.damage is not None:
            number = self.damage.get_single()
            if number is None:
                return
            damage = float(number)
        
        array = self.damageables.get_array()
        new_array = [None] * len(array)

        requires_change = False
        for i in range(len(array)):
            value = array[i]
            if isinstance(value, ItemType):
                item_type = value
                item_stack = item_type.random()

                if self.damage is None:
                    ItemUtils.set_damage(item_stack, 0)
                else:
                    ItemUtils.set_damage(item_stack, int(Math2.fit(0, ItemUtils.get_damage(item_stack) + (self.heal and -damage or damage), item_stack.type().max_durability())))
                
                new_array[i] = ItemType(item_stack)
                requires_change = True
            elif isinstance(value, LivingEntity):
                living_entity = value
                if not self.heal:
                    HealthUtils.damage(living_entity, damage)
                else:
                    if self.damage is None:
                        HealthUtils.set_health(living_entity, HealthUtils.max_health(living_entity))
                    else:
                        HealthUtils.heal(living_entity, damage)

                new_array[i] = living_entity
        
        if requires_change:
            self.damageables.change(new_array, ChangeMode.SET)
