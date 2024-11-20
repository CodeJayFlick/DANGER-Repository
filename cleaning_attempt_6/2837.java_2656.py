class ImmutableRectangle2D:
    def __init__(self, x1: object, x2: object, y1: object, y2: object, space):
        assert isinstance(space, EuclideanSpace2D)
        self.x1 = x1
        self.x2 = x2
        self.y1 = y1
        self.y2 = y2
        self.space = space

    def __str__(self):
        return f"rect[{self.x1}-{self.x2}]x[{self.y1}-{self.y2}]"

    def description(self):
        return str(self)

    @property
    def x1(self):
        return self.x1

    @property
    def x2(self):
        return self.x2

    @property
    def y1(self):
        return self.y1

    @property
    def y2(self):
        return self.y2

    @property
    def space(self):
        return self.space

    def __eq__(self, other):
        if isinstance(other, ImmutableRectangle2D):
            return (isinstance(other, EuclideanSpace2D) and 
                   self.x1 == other.x1 and self.x2 == other.x2 and 
                   self.y1 == other.y1 and self.y2 == other.y2)
        else:
            return False

    def __hash__(self):
        return hash((self.x1, self.x2, self.y1, self.y2))
