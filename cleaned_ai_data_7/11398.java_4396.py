class AssemblyGrammar:
    def __init__(self):
        self.semantics = {}
        self.pure_recursive = {}

    def new_production(self, lhs, rhs):
        return {'lhs': lhs, 'rhs': rhs}

    def add_production(self, prod):
        if self.is_pure_recursive(prod['lhs']):
            self.pure_recursive[prod['lhs'].name] = prod
        else:
            super().add_production(prod)

    @staticmethod
    def is_pure_recursive(lhs):
        return True  # Replace this with your actual logic

    def add_production_with_semantics(self, lhs, rhs, pattern, cons, indices):
        prod = self.new_production(lhs, rhs)
        if not self.semantics.get(cons):
            self.semantics[cons] = {'pattern': None, 'indices': []}
        sem = self.semantics[cons]
        if sem['pattern'] is None:
            sem['pattern'] = pattern
            sem['indices'].extend(indices)

    def get_semantics(self, prod):
        return list(self.semantics.values())

    @staticmethod
    def combine(assembly_grammar1, assembly_grammar2):
        for key in set(list(assembly_grammar1.semantics.keys()) + list(assembly_grammar2.semantics.keys())):
            if key in assembly_grammar1.semantics:
                assembly_grammar1.semantics[key].update(assembly_grammar2.semantics.get(key, {}))
            else:
                assembly_grammar1.semantics.update({key: v for k, v in assembly_grammar2.semantics.items()})
        return assembly_grammar1

    def get_pure_recursive(self):
        return list(self.pure_recursive.values())

    def get_pure_recursion(self, lhs):
        return self.pure_recursive.get(lhs.name)
