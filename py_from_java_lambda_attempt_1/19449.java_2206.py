Here is the translation of the given Java code into Python:

```Python
class EvtDamage:
    def __init__(self):
        pass

    @staticmethod
    def register_event():
        Skript.register_event("damage", EvtDamage, EntityDamageEvent, "damag(e|ing) [of %entitydata%]")
        Skript.description("Called when an entity receives damage, e.g. by an attack from another entity, lava, fire, drowning, fall, suffocation, etc.")
        Skript.examples(["on damage:", "on damage of a player:"])
        Skript.since("1.0")

    @staticmethod
    def check_type(e):
        if EvtDamage.types is not None:
            for d in EvtDamage.types.get_all():
                if d.is_instance(e):
                    return True
        return False

    @staticmethod
    def check_damage(e):
        if isinstance(e.entity, LivingEntity) and HealthUtils.get_health(e.entity) <= 0:
            return False
#         if e.entity.no_damage_ticks() <= e.entity.maximum_no_damage_ticks() / 2: 
#             EvtDamage.last_damages[e.entity] = e.damage()
#             return True
#         last_damage = EvtDamage.last_damages.get(e.entity)
#         if last_damage is not None and last_damage >= e.damage():
#             return False
#         EvtDamage.last_damages[e.entity] = e.damage()

    @staticmethod
    def __str__(self, e=None, debug=False):
        return "damage" + (" of " + str(EvtDamage.types) if EvtDamage.types is not None else "")

class Skript:
    register_event = staticmethod(lambda: pass)
    description = staticmethod(lambda s: print(s))
    examples = staticmethod(lambda *args: [str(arg) for arg in args])
    since = staticmethod(lambda s: print(s))

#     @staticmethod
#     def info(self, message):
#         print(message)

class EntityData:
    is_instance = staticmethod(lambda self, e: isinstance(e, self.__class__))

class LivingEntity:
    no_damage_ticks = property(get_no_damage_ticks)
    maximum_no_damage_ticks = property(get_maximum_no_damage_ticks)
    health = property(get_health)

def get_no_damage_ticks(self):
    pass

def get_maximum_no_damage_ticks(self):
    pass

def get_health(self):
    pass
```

Please note that the Java code provided is quite complex and has many dependencies. The translation to Python may not be perfect, as some parts of the original code might have been simplified or modified for better compatibility with Python's syntax and semantics.