Here's a translation of your Java code into equivalent Python:

```Python
class Attacked:
    def __init__(self):
        self.type = None

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if isinstance(value, str) and not value.strip():
            self._type = EntityData.from_class(Entity)
        elif isinstance(value, str):
            try:
                self._type = EntityData.parse(value)
            except ValueError as e:
                print(f"'{value}' is not an entity type: {e}")
                return
        else:
            if isinstance(self._type, (EntityData)):
                pass  # No error here
            else:
                raise TypeError("Invalid 'type' value")

    def init(self):
        if Skript.current_event in [EntityDamageEvent, EntityDeathEvent, VehicleDamageEvent, VehicleDestroyEvent]:
            return True
        print(f"The expression '{self.__class__.__name__}' can only be used in a damage or death event")
        return False

    @property
    def parser(self):
        return Skript.parser

    def get(self, e):
        if isinstance(e, (EntityEvent)):
            entity = e.get_entity()
        elif isinstance(e, (VehicleEvent)):
            entity = e.get_vehicle()
        else:
            raise TypeError("Invalid event type")
        if self.type.is_instance(entity):
            return [entity]
        return []

    def get_return_type(self):
        return self.type.type

    @property
    def is_single(self):
        return True


class EntityData:
    from_class = None  # This should be a class method, not an instance variable.

    @classmethod
    def from_class(cls, entity):
        if isinstance(entity, type) and issubclass(entity, (Entity)):
            return cls(entity)
        else:
            raise TypeError("Invalid 'entity' value")

    @staticmethod
    def parse(value):
        try:
            # This should be a class method or static method.
            pass  # No implementation here. You would need to implement this based on your requirements.
        except ValueError as e:
            print(f"'{value}' is not an entity type: {e}")
            return None
```

This Python code doesn't have direct equivalent of Java's `@Name`, `@Description`, etc., annotations, but you can achieve similar functionality using docstrings and comments.