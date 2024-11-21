class IsSwimming:
    def __init__(self):
        pass

    @property
    def description(self):
        return "Checks whether a living entity is swimming."

    @property
    def examples(self):
        return ["player is swimming"]

    @property
    def name(self):
        return "Is Swimming"

    @property
    def required_plugins(self):
        return "1.13 or newer"

    @property
    def since(self):
        return "2.3"


def check(e):
    if hasattr(e, 'is_swimming'):
        return e.is_swimming()
    else:
        raise AttributeError("The entity is not a living entity")


class PropertyCondition(IsSwimming):
    pass


if __name__ == "__main__":
    # You can test the class here
    print(check(LivingEntity()))
