class ArrowPierceLevel:
    def __init__(self):
        self.can_use_pierce = hasattr(Arrow, 'getPierceLevel')

    @property
    def name(self):
        return "Arrow Pierce Level"

    @property
    def description(self):
        return "An arrow's pierce level."

    @property
    def examples(self):
        return ["on shoot:",
                "\tevent-projectile is an arrow",
                "\tset arrow pierce level of event-projectile to 5"]

    @property
    def required_plugins(self):
        return ["Minecraft 1.14+"]

    @property
    def since(self):
        return "2.5.1"

    def convert(self, arrow: Projectile) -> int:
        if isinstance(arrow, Arrow):
            return (arrow).getPierceLevel()
        else:
            raise ValueError("Invalid projectile")

    def accept_change(self, mode: str) -> list:
        if mode in ["SET", "RESET", "REMOVE", "ADD"]:
            return [int]
        else:
            return None

    def change(self, e, delta=None, mode=""):
        strength = 0
        mod = 1
        if mode == "REMOVE":
            mod = -1
        elif mode == "ADD":
            for entity in get_expr().get_array(e):
                if isinstance(entity, Arrow):
                    arrow = entity
                    dmg = math.floor(arrow.getPierceLevel() + strength * mod)
                    if dmg < 0:
                        dmg = 0
                    arrow.setPierceLevel(dmg)

        elif mode == "RESET" or mode == "SET":
            for entity in get_expr().get_array(e):
                if isinstance(entity, Arrow):
                    ((Arrow)entity).setPierceLevel(strength)
