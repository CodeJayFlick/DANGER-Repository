class CondIsInWorld:
    def __init__(self):
        self.entities = None
        self.worlds = None

    @staticmethod
    def register():
        PropertyCondition.register(CondIsInWorld, "in [[the] worlds] %worlds%", "entities")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) != 2:
            raise ValueError("Expected two expressions")
        self.entities = exprs[0]
        self.worlds = exprs[1]
        self.set_negated(matched_pattern == 1)
        return True

    def check(self, e):
        for entity in self.entities.check(e):
            if is_negated():
                return not any(entity.get_world() == world for world in self.worlds.check(e))
            else:
                return all(entity.get_world() == world for world in self.worlds.check(e))

    def __str__(self, e=None, debug=False):
        return f"{PropertyCondition.__str__(self)} be {'' if not is_negated() else 'not '}in the {'world' if len(self.worlds) == 1 else 'worlds'} {self.worlds}"
