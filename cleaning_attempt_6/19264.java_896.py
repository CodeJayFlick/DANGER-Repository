class IsRiptiding:
    def __init__(self):
        pass

    @property
    def description(self):
        return "Checks to see if an entity is currently using the Riptide enchantment."

    @property
    def examples(self):
        return ["target entity is riptiding"]

    @property
    def since(self):
        return "2.5"

    @property
    def name(self):
        return "Is Riptiding"


def check(entity):
    if hasattr(entity, 'isRiptiding'):
        return entity.isRiptiding()
    else:
        return False


class CondIsRiptiding(IsRiptiding):
    pass

# Register the class
CondIsRiptiding.register = lambda: None  # This is a hack to mimic Java's static block registration.
register("riptiding", "livingentities")
