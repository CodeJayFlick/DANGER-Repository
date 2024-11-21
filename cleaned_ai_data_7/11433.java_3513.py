class AssemblyTerminal:
    def __init__(self, name):
        self.name = name

    def match(self, buffer: str, pos: int, grammar, labels) -> list:
        pass  # abstract method implementation left to subclasses

    def get_suggestions(self, got: str, labels) -> list:
        pass  # abstract method implementation left to subclasses
