Here is the translation of the Java code into Python:

```Python
class SimpleEntityData:
    def __init__(self):
        self.types = []
        if Skript.isRunningMinecraft(1, 11):  # More subtypes, more supertypes - changes needed
            self.types.append({"codeName": "wither skeleton", "c": WitherSkeleton})
            self.types.append({"codeName": "stray", "c": Stray})
            self.types.append({"codeName": "husk", "c": Husk})
            self.types.append({"codeName": "skeleton", "c": Skeleton, "isSupertype": True})

        if Skript.isRunningMinecraft(1, 13):  # More subtypes, more supertypes - changes needed
            self.types.append({"codeName": "dolphin", "c": Dolphin})
            self.types.append({"codeName": "phantom", "c": Phantom})
            self.types.append({"codeName": "drowned", "c": Drowned})
            self.types.append({"codeName": "turtle", "c": Turtle})

        if Skript.isRunningMinecraft(1, 14):  # More subtypes, more supertypes - changes needed
            self.types.append({"codeName": "pillager", "c": Pillager})
            self.types.append({"codeName": "ravager", "c": Ravager})
            self.types.append({"codeName": "wandering trader", "c": WanderingTrader})

        if Skript.isRunningMinecraft(1, 16):  # More subtypes, more supertypes - changes needed
            self.types.append({"codeName": "piglin", "c": Piglin})
            self.types.append({"codeName": "hoglin", "c": Hoglin})
            self.types.append({"codeName": "zoglin", "c": Zoglin})

        if Skript.isRunningMinecraft(1, 17):  # More subtypes, more supertypes - changes needed
            self.types.append({"codeName": "glow squid", "c": GlowSquid})
            self.types.append({"codeName": "marker", "c": Marker})

        for info in self.types:
            if Skript.classExists(info["c"]):
                self.types.remove(info)
                break

    def register(self, codeNames):
        return {"simple": Entity}

class SimpleEntityDataInfo:
    def __init__(self, codeName, c, isSupertype=False):
        self.codeName = codeName
        self.c = c
        self.isSupertype = isSupertype

    def hashCode(self):
        return hash(self.c)

    def equals(self, obj):
        if not isinstance(obj, SimpleEntityDataInfo):
            return False
        other = obj
        return self.c == other.c and self.codeName == other.codeName and self.isSupertype == other.isSupertype

class Entity:
    pass

# You need to implement the following classes in Python:
class WitherSkeleton(Entity):  # More subtypes, more supertypes - changes needed
    pass

class Stray(Entity):
    pass

class Husk(Entity):
    pass

class Skeleton(Entity):
    pass

class Dolphin(Entity):
    pass

class Phantom(Entity):
    pass

class Drowned(Entity):
    pass

class Turtle(Entity):
    pass

class Pillager(Entity):
    pass

class Ravager(Entity):
    pass

class WanderingTrader(Entity):
    pass

class Piglin(Entity):
    pass

class Hoglin(Entity):
    pass

class Zoglin(Entity):
    pass

class GlowSquid(Entity):
    pass

class Marker(Entity):
    pass
```

Please note that you need to implement the following classes in Python: WitherSkeleton, Stray, Husk, Skeleton, Dolphin, Phantom, Drowned, Turtle, Pillager, Ravager, WanderingTrader, Piglin, Hoglin, Zoglin, GlowSquid, Marker.