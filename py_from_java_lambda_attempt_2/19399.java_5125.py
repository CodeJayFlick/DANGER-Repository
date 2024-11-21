Here is the translation of the Java code to Python:

```Python
import random

class BeeData:
    def __init__(self):
        self.nectar = 0
        self(angry=0)

    @staticmethod
    def register():
        if hasattr(org.bukkit.entity, 'Bee'):
            EntityData.register(BeeData, "bee", org.bukkit.entity.Bee, 2,
                                 "no nectar bee", "happy bee", "bee", "nectar bee",
                                 "angry bee", "angry nectar bee")

    def init(self, exprs, matched_pattern):
        if matched_pattern > 3:
            self(angry=1)
        elif matched_pattern < 2:
            self(angry=-1)
        if matched_pattern == 3 or matched_pattern == 5:
            self(nectar=1)
        else:
            self(nectar=-1)

    def init(self, c=None, e=None):
        if e is None:
            self(angry=0)
            self(nectar=0)
        elif e.get_anger() > 0:
            self(angry=1)
        else:
            self(angry=-1)
        if e.has_nectar():
            self(nectar=1)
        else:
            self(nectar=-1)

    def set(self, entity):
        random_number = random.randint(400) + 400
        entity.set_anger(random_number if self(angry=1) else 0)
        entity.set_has_nectar(self.nectar > 0)

    def match(self, entity):
        return (self(angry=0) or (entity.get_anger() > 0) == (self(angry=1))) and \
               (self(nectar=0) or entity.has_nectar() == self(nectar))

    @property
    def type(self):
        return org.bukkit.entity.Bee

    def __hash__(self):
        prime = 31
        result = 1
        result *= prime + self(angry)
        result *= prime + self.nectar
        return result

    def __eq__(self, other):
        if not isinstance(other, BeeData):
            return False
        return (self(angry) == other(angry)) and \
               (self(nectar) == other(nectar))

    @property
    def super_type(self):
        return self.__class__()
```

Please note that Python does not have direct equivalent of Java's static methods, annotations or generics. Also, some concepts like `EntityData` are missing in the provided code and might need to be implemented separately for this translation to work correctly.