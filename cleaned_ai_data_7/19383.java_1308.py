class Spawn:
    def __init__(self):
        self.locations = None
        self.types = None
        self.amount = 1

    @staticmethod
    def register_effect():
        Skript.register_effect("spawn|summon %entitytypes% [%directions% %locations%]",
                               "spawn|summon %number% of %entitytypes% [%directions% %locations%]")

    def init(self, exprs):
        if len(exprs) == 0:
            self.amount = None
        else:
            self.amount = int(exprs[0])
        self.types = exprs[1]
        self.locations = Direction.combine(exprs[2], exprs[3])

    @staticmethod
    def last_spawned():
        return None

    def execute(self, e):
        if self.amount is not None and self.amount > 0:
            for location in self.locations:
                for type in self.types:
                    for _ in range(int(self.amount)):
                        Spawn.last_spawned = type.data.spawn(location)

    def __str__(self, e=None, debug=False):
        return "spawn" + (" " + str(self.amount) if self.amount is not None else "") + " " + str(self.types) + " " + str(self.locations)
