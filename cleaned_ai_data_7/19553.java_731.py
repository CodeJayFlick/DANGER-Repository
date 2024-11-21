class EntityTamer:
    def __init__(self):
        pass

    @property
    def description(self):
        return "The owner of a tameable entity, such as a horse or wolf."

    @property
    def examples(self):
        return ["set owner of target entity to player", 
                "delete owner of target entity",
                "set {_t} to uuid of tamer of target entity"]

    @property
    def since(self):
        return "2.5"

    def accept_change(self, mode):
        if mode in [ChangeMode.SET, ChangeMode.DELETE, ChangeMode.RESET]:
            return [OfflinePlayer]
        else:
            return None

class OfflinePlayer:
    pass

def convert(entity):
    if isinstance(entity, Tameable) and entity.is_tamed():
        return entity.get_owner()
    else:
        return None

def change(e, delta, mode):
    player = delta[0] if delta is not None else None
    if mode == ChangeMode.SET:
        for entity in get_expr().get_all(e):
            if isinstance(entity, Tameable) and not entity.is_tamed():
                continue
            entity.set_owner(player)
    elif mode in [ChangeMode.DELETE, ChangeMode.RESET]:
        for entity in get_expr().get_all(e):
            if isinstance(entity, Tameable) and not entity.is_tamed():
                continue
            entity.set_owner(None)

def get_return_type(self):
    return OfflinePlayer

def get_property_name(self):
    return "entity owner"

class SimplePropertyExpression:
    def __init__(self, expr):
        self.expr = expr

    def get_all(self, e):
        pass  # This method should be implemented based on the actual expression.

    def to_string(self, e, d):
        return f"owner of {self.expr.to_string(e, d)}"

class Tameable:
    @property
    def is_tamed(self):
        pass

    def get_owner(self):
        pass

    def set_owner(self, owner):
        pass

# Register the class for use in expressions.
register(EntityTamer)
