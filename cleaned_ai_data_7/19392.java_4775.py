class VectorRotateAroundAnother:
    def __init__(self):
        self.first = None
        self.second = None
        self.degree = None

    @staticmethod
    def register_effect():
        Skript.register_effect(VectorRotateAroundAnother, "rotate %vectors% around %vector% by %number% [degrees]")

    def init(self, exprs, matched_pattern):
        if len(exprs) != 3:
            return False
        self.first = exprs[0]
        self.second = exprs[1]
        self.degree = exprs[2]
        return True

    def execute(self, e):
        v2 = self.second.get_single(e)
        d = self.degree.get_single(e)
        if v2 is None or d is None:
            return
        for v1 in self.first.get_array(e):
            VectorMath.rot(v1, v2, float(d))

    def __str__(self, e, debug=False):
        return f"rotate {self.first} around {self.second} by {self.degree} degrees"
