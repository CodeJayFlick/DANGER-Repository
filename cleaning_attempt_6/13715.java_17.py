class Hayes:
    def __init__(self):
        pass

    def accept(self, visitor):
        if isinstance(visitor, HayesVisitor):
            visitor.visit(self)
        else:
            print("Only HayesVisitor is allowed to visit Hayes modem")

    def __str__(self):
        return "Hayes modem"
