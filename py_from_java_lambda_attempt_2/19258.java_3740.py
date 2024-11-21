Here is the translation of the given Java code into Python:

```Python
class IsOnGround:
    def __init__(self):
        pass

    @property
    def description(self) -> str:
        return "Checks whether an entity is on ground."

    @property
    def examples(self) -> str:
        return "player is not on ground"

    @property
    def since(self) -> str:
        return "2.2-dev26"

    @property
    def name(self) -> str:
        return "Is on Ground"


def check(entity):
    if hasattr(entity, 'is_on_ground'):
        return entity.is_on_ground()
    else:
        raise AttributeError("Entity does not have an is_on_ground method")


class CondIsOnGround(IsOnGround):
    @property
    def property_name(self) -> str:
        return "on ground"

    def __call__(self, entity: object) -> bool:
        if hasattr(entity, 'is_on_ground'):
            return check(entity)
        else:
            raise AttributeError("Entity does not have an is_on_ground method")
```

Please note that Python doesn't support Java-like annotations like `@Name`, `@Description` etc. Instead, we define these as properties of the class in this translation.