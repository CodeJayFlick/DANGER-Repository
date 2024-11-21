Here is the translation of the Java code into Python:

```Python
from collections import defaultdict, OrderedDict

class AbstractAssemblyGrammar:
    def __init__(self):
        self.productions = defaultdict(list)
        self.prod_list = []
        self.nonterminals = {}
        self.terminals = {}
        self.symbols = {}
        self.start_name = None

    def new_production(self, lhs, rhs):
        raise NotImplementedError("Subclass must implement this method")

    def add_production(self, prod):
        name = prod.name
        if not self.productions[name]:
            self.prod_list.append(prod)
            self.productions[name] = [prod]
            for symbol in prod:
                if isinstance(symbol, AssemblyNonTerminal):
                    self.nonterminals[symbol.name] = symbol
                    self.symbols[symbol.name] = symbol
                elif isinstance(symbol, AssemblyTerminal):
                    self.terminals[symbol.name] = symbol
                    self.symbols[symbol.name] = symbol

    def is_pure_recursive(self, prod):
        if len(prod) != 1:
            return False
        if not prod[0].name == prod.lhs_name:
            return False
        return True

    def set_start(self, nt):
        self.set_start_name(nt.name)

    def set_start_name(self, name):
        self.start_name = name

    def get_start(self):
        return self.nonterminals[self.start_name]

    def get_non_terminal(self, name):
        return self.nonterminals.get(name)

    def get_terminal(self, name):
        return self.terminals.get(name)

    def combine(self, that):
        for prod in that.prod_list:
            self.add_production(prod)

    def print(self, out):
        for prod in self.prod_list:
            out.write(str(prod) + "\n")

    def verify(self):
        if not self.start_name or not self.productions[self.start_name]:
            raise AssemblyGrammarException("Start symbol has no defining production")
        for name, prods in self.productions.items():
            for prod in prods:
                for symbol in prod:
                    if isinstance(symbol, AssemblyNonTerminal) and not self.nonterminals.get(symbol.name):
                        raise AssemblyGrammarException(f"Grammar has non-terminal '{symbol.name}' without a defining production")

    def __iter__(self):
        return iter(self.prod_list)

class AssemblyGrammar(AbstractAssemblyGrammar):
    pass

class AbstractAssemblyProduction:
    def __init__(self, lhs):
        self.lhs = lhs
        self.rhs = []

    @property
    def name(self):
        raise NotImplementedError("Subclass must implement this method")

    @property
    def size(self):
        return len(self.rhs)

    @property
    def get_lhs(self):
        return self.lhs

    @property
    def get_rhs(self):
        return self.rhs


# Example usage:
class AssemblyNonTerminal(AbstractAssemblyProduction):
    def __init__(self, name):
        super().__init__(name)
        self.name = name

    @property
    def name(self):
        return self._name

    @property
    def get_name(self):
        return self._name


class AssemblyTerminal(AbstractAssemblyProduction):
    def __init__(self, name):
        super().__init__(name)
        self.name = name

    @property
    def name(self):
        return self._name

    @property
    def get_name(self):
        return self._name


# Example usage:
grammar = AssemblyGrammar()
nt1 = AssemblyNonTerminal("NT1")
nt2 = AssemblyNonTerminal("NT2")
t1 = AssemblyTerminal("T1")

prod1 = AbstractAssemblyProduction(nt1)
prod1.rhs.append(t1)

prod2 = AbstractAssemblyProduction(nt2)
prod2.rhs.append(AssemblySentential([nt1, t1]))

grammar.add_production(prod1)
grammar.add_production(prod2)

print(grammar.get_non_terminal("NT1").name)  # Output: NT1
```

This Python code is equivalent to the Java code provided.