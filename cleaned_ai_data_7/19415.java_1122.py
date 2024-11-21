class MooshroomData:
    def __init__(self):
        pass

    @classmethod
    def register(cls):
        if hasattr(Skript, 'method_exists') and Skript.method_exists(MushroomCow, 'get_variant'):
            EntityData.register(cls, "mooshroom", MushroomCow, 1,
                                "mooshroom", "red mooshroom", "brown mooshroom")

    @property
    def variant(self):
        return self._variant

    @variant.setter
    def variant(self, value):
        if isinstance(value, Variant):
            self._variant = value
            super().matched_pattern = 2 if value == Variant.BROWN else 1
        elif value is None:
            self._variant = None
            super().matched_pattern = 0

    @classmethod
    def from_exprs(cls, exprs, matched_pattern, parse_result):
        if matched_pattern > 0:
            return cls(Variant(values()[matched_pattern - 1]))
        else:
            return cls()

    @classmethod
    def from_entity(cls, c, mushroom_cow):
        if mushroom_cow is not None:
            return cls(mushroom_cow.get_variant())
        else:
            return cls(None)

    def set(self, entity):
        if self.variant is not None:
            entity.set_variant(self.variant)

    def match(self, entity):
        return self.variant == entity.get_variant() or self.variant is None

    @classmethod
    def get_type(cls):
        return MushroomCow

    @property
    def super_type(self):
        return MooshroomData(self.variant)

    def __hash__(self):
        if self.variant is not None:
            return hash(self.variant)
        else:
            return 0

    def __eq__(self, other):
        if isinstance(other, MooshroomData) and self.variant == other.variant:
            return True
        elif type(other) != MooshroomData:
            return False
        else:
            return False

    @classmethod
    def is_supertype_of(cls, data):
        if not isinstance(data, MooshroomData):
            return False
        return self.variant is None or self.variant == (data).variant
