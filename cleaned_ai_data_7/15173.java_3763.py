class Unit:
    def __init__(self, *children):
        self.children = list(children)

    def accept(self, visitor):
        for child in self.children:
            child.accept(visitor)
