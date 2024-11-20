Here is the translation of the Java code to Python:

```Python
class ParrotData:
    def __init__(self):
        pass

    @staticmethod
    def register():
        if hasattr(Skript, 'Parrot'):
            variants = list(Parrot.Variant)
            EntityData.register('parrot', Parrot, 0,
                                 "parrot", "red parrot", "blue parrot",
                                 "green parrot", "cyan parrot", "gray parrot")

    def __init__(self, variant=-1):
        self.variant = variant
        super().matched_pattern = variant + 1

    @staticmethod
    def init(exprs, matched_pattern, parse_result):
        if matched_pattern == 0:
            return -1
        else:
            return matched_pattern - 1

    def set(self, entity):
        if self.variant == -1:
            random_variant = ThreadLocalRandom.current().nextInt(0, len(variants))
            entity.set_variant(variants[random_variant])
        else:
            entity.set_variant(variants[self.variant])

    @staticmethod
    def match(entity):
        return self.variant == -1 or entity.get_variant() == variants[self.variant]

    def get_type(self):
        return Parrot

    def get_super_type(self):
        return type(self)(self.variant)

    def __hash__(self):
        return hash(self.variant)

    def __eq__(self, other):
        if isinstance(other, ParrotData):
            return self.variant == other.variant
        return False

    @staticmethod
    def is_supertype_of(e):
        if isinstance(e, ParrotData) and (self.variant == -1 or e.variant == self.variant):
            return True
        return False


class EntityData:
    register = None

    class Skript:
        Parrot = None

    class ThreadLocalRandom:
        current = None

    variants = []

    def __init__(self, variant=-1):
        pass

    @staticmethod
    def init(exprs, matched_pattern, parse_result):
        return True

    def set(self, entity):
        if self.variant == -1:
            random_variant = ThreadLocalRandom.current().nextInt(0, len(variants))
            entity.set_variant(variants[random_variant])
        else:
            entity.set_variant(variants[self.variant])

    @staticmethod
    def match(entity):
        return True

    def get_type(self):
        return None

    def get_super_type(self):
        return type(self)(self.variant)

    def __hash__(self):
        return 0

    def __eq__(self, other):
        if isinstance(other, EntityData):
            return False
        return False


class Parrot:
    Variant = []

    @staticmethod
    def set_variant(variant):
        pass

    def get_variant(self):
        return None

    class Skript:
        Parrot = None
```

Please note that this translation is not perfect and some parts of the code might be missing or incorrect. The original Java code seems to have been written for a specific framework (Skript) which doesn't exist in Python, so I had to make assumptions about how it should work.