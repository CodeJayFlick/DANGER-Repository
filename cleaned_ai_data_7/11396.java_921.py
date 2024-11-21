class AssemblyExtendedGrammar:
    def __init__(self):
        pass

    def new_production(self, lhs: 'AssemblyExtendedNonTerminal', rhs: 'AssemblySentential[AssemblyExtendedNonTerminal]'):
        raise Exception("Please construct extended productions yourself")
