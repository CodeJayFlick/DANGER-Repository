class AssemblyExtendedProduction:
    def __init__(self, lhs, rhs, final_state, ancestor):
        self.lhs = lhs
        self.rhs = rhs
        self.final_state = final_state
        self.ancestor = ancestor

    @property
    def get_lhs(self):
        return self.lhs

    def get_final_state(self):
        return self.final_state

    def get_ancestor(self):
        return self.ancestor


class AssemblyExtendedNonTerminal:
    pass


class AssemblySentential:
    pass


# Example usage:

lhs = "some extended left-hand side"
rhs = "some extended right-hand side"
final_state = 123
ancestor = None

production = AssemblyExtendedProduction(lhs, rhs, final_state, ancestor)

print(production.get_lhs)  # prints: some extended left-hand side
print(production.get_final_state())  # prints: 123
print(production.get_ancestor())  # prints: None
