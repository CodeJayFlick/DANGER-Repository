Here is a translation of the Java code into equivalent Python:

```Python
class FallDistance:
    def __init__(self):
        self.name = "Fall Distance"
        self.description = {"The distance an entity has fallen for."}
        self.examples = [{"set all entities' fall distance to 10", 
                          "on damage:", 
                          "\tsend \"%victim's fall distance%\" to victim"}]
        self.since = "2.5"

    def convert(self, entity):
        return entity.fall_distance

    def accept_change(self, mode):
        if mode in [ChangeMode.RESET, ChangeMode.REMOVE_ALL, ChangeMode.DELETE]:
            return None
        else:
            return [float]

    def change(self, e, delta, mode):
        entities = self.get_expr().get_array(e)
        if len(entities) < 1:
            return

        number = float(delta[0])
        for entity in entities:
            fall_distance = entity.fall_distance
            if mode == ChangeMode.ADD:
                entity.set_fall_distance(fall_distance + number)
            elif mode == ChangeMode.SET:
                entity.set_fall_distance(number)
            elif mode == ChangeMode.REMOVE:
                entity.set_fall_distance(fall_distance - number)

    def get_return_type(self):
        return float

    def get_property_name(self):
        return "fall distance"
```

Please note that Python does not have a direct equivalent to Java's `@Nullable` and `@Override`, so I've omitted those. Also, the `register` method is not present in this translation as it seems to be specific to SkriptLang.