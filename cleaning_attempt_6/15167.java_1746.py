class Commander:
    def __init__(self, *children):
        super().__init__(*children)

    def accept(self, visitor):
        visitor.visit_commander(self)
        super().accept(visitor)

    def __str__(self):
        return "commander"
