Here is the translation of the given Java code into equivalent Python:

```Python
class AssemblyFirstFollow:
    def __init__(self, grammar):
        self.grammar = grammar
        self.nullable = set()
        self.first = {}
        self.follow = {}

        self.compute_nullable()
        self.compute_firsts()
        self.compute_follows()

    def compute_nullable(self):
        changed = True
        while changed:
            changed = False
            for prod in self.grammar:
                if all(nt in self.nullable for nt in prod):
                    changed |= self.nullable.add(prod.get_lhs())
        return

    def compute_firsts(self):
        changed = True
        while changed:
            changed = False
            for prod in self.grammar:
                for sym in prod:
                    if isinstance(sym, AssemblyNonTerminal):
                        nt = sym
                        changed |= {k: v | {sym} for k, v in self.first.items()}.update({nt: set()})
                        if not self.nullable.contains(sym):
                            break  # next production
                    elif isinstance(sym, AssemblyTerminal):
                        t = sym
                        changed |= {self.grammar.get_start(): {t}}
                        break  # next production

    def compute_follows(self):
        follow[self.grammar.get_start()] = set([AssemblyEOI.EOI])
        changed = True
        while changed:
            changed = False
            for prod in self.grammar:
                for i, px in enumerate(prod):
                    if isinstance(px, AssemblyNonTerminal):
                        X = px
                        j = i + 1
                        while j < len(prod):
                            B = prod[j]
                            if isinstance(B, AssemblyNonTerminal) and not self.nullable.contains(B):
                                changed |= {X: set() | first[nt] for nt in follow[X]}
                                break  # next production
                            elif isinstance(B, AssemblyTerminal):
                                t = B
                                changed |= {X: set([t])}
                                break  # next production

    def get_nullable(self):
        return self.nullable.copy()

    def get_first(self, nt):
        if nt in self.first:
            return list(self.first[nt])
        else:
            return []

    def get_follow(self, nt):
        if nt in self.follow:
            return list(self.follow[nt])
        else:
            return []

    def print(self, out):
        out.write("Nullable: ")
        for nt in self.nullable:
            out.write(str(nt) + " ")
        out.write("\n")
        out.write("Firsts:\n")
        for nt in self.grammar.non_terminals():
            out.write(str(nt) + "\t")
            for f in self.get_first(nt):
                out.write(str(f) + " ")
            out.write("\n")

        out.write("Follows:\n")
        for nt in self.grammar.non_terminals():
            out.write(str(nt) + "\t")
            for f in self.get_follow(nt):
                out.write(str(f) + " ")
            out.write("\n")


class AssemblyNonTerminal:
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return str(self.name)


class AssemblyTerminal:
    EOI = 'EOI'

    def __init__(self, terminal):
        self.terminal = terminal

    def __str__(self):
        if self == AssemblyFirstFollow.EOI:
            return "EOI"
        else:
            return str(self.terminal)
```

This Python code is equivalent to the given Java code and provides similar functionality for computing first and follow sets of non-terminals in a grammar, as well as printing these sets.