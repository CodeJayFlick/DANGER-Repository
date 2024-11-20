class Zoom:
    def __init__(self):
        pass

    def accept(self, visitor):
        if isinstance(visitor, ZoomVisitor):
            visitor.visit(self)
        else:
            print("Only ZoomVisitor is allowed to visit Zoom modem")

    def __str__(self):
        return "Zoom modem"
