class RabbitData:
    def __init__(self):
        pass

    @staticmethod
    def register():
        if hasattr(Skript, 'Rabbit'):
            EntityData.register(RabbitData, "rabbit", Rabbit, 0, "rabbit", "black rabbit", "black and white rabbit",
                                 "brown rabbit", "gold rabbit", "salt and pepper rabbit", "killer rabbit", "white rabbit")
        return

    def __init__(self, type=0):
        self.type = type
        super().matched_pattern = type

    @staticmethod
    def int_from_type(type):
        if type == Rabbit.Type.BLACK:
            return 1
        elif type == Rabbit.Type.BLACK_AND_WHITE:
            return 2
        elif type == Rabbit.Type.BROWN:
            return 3
        elif type == Rabbit.Type.GOLD:
            return 4
        elif type == Rabbit.Type.SALT_AND_PEPPER:
            return 5
        elif type == Rabbit.Type.THE_KILLER_BUNNY:
            return 6
        elif type == Rabbit.Type.WHITE:
            return 7

    @staticmethod
    def type_from_int(i):
        if i == 1:
            return Rabbit.Type.BLACK
        elif i == 2:
            return Rabbit.Type.BLACK_AND_WHITE
        elif i == 3:
            return Rabbit.Type.BROWN
        elif i == 4:
            return Rabbit.Type.GOLD
        elif i == 5:
            return Rabbit.Type.SALT_AND_PEPPER
        elif i == 6:
            return Rabbit.Type.THE_KILLER_BUNNY
        elif i == 7:
            return Rabbit.Type.WHITE

    def init(self, exprs=None, matched_pattern=0):
        self.type = matched_pattern
        return True

    def set(self, entity):
        if self.type != 0:
            entity.set_rabbit_type(self.type_from_int(self.type))

    def match(self, entity):
        return self.type == 0 or self.int_from_type(entity.get_rabbit_type()) == self.type

    @property
    def type_(self):
        return Rabbit.Type

    def get_super_type(self):
        return RabbitData()

    def __hash__(self):
        return hash(self.type)

    def __eq__(self, other):
        if not isinstance(other, RabbitData):
            return False
        return self.type == other.type

    def is_supertype_of(self, e):
        if isinstance(e, RabbitData) and (self.type == 0 or type_from_int((e).type) == self.type):
            return True
