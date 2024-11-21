Here is your Java code translated into Python:

```Python
import collections

class AssemblyGrammar:
    def __init__(self):
        self.productions = []

    def add_production(self, lhs, *objs):
        rhs = []
        for obj in objs:
            if isinstance(obj, str) and "  ".equals(obj):
                rhs.append(None)
            elif isinstance(obj, str):
                rhs.append(AssemblyStringTerminal(obj))
            else:
                raise TypeError("Type mismatch: {}".format(obj))
        self.productions.append((lhs, AssemblySentential(rhs)))

    def print(self, out=None):
        if not hasattr(out, "write"):
            return
        for production in self.productions:
            lhs = str(production[0])
            rhs = [str(x) if x is None else str(x.value) for x in production[1]]
            out.write("{}: {}\n".format(lhs, ", ".join(rhs)))

class AssemblyNonTerminal(str):
    pass

class AssemblyStringTerminal(str):
    pass

class AssemblySentential(list):
    def __init__(self, items=None):
        super().__init__()
        if items is not None:
            self.extend(items)

class ParserTest:
    def test_first_follow(self):
        g = AssemblyGrammar()
        E = AssemblyNonTerminal("E")
        T = AssemblyNonTerminal("T")
        F = AssemblyNonTerminal("F")

        g.add_production(E, [E, "+", T])
        g.add_production(T, [T, "*", F])

        out = print_stream() if self.tracing else null_output()
        g.print(out)
        out.write("Computing sets\n")
        ff = FirstFollow(g)

        print_first_follow(ff, g)

    def test_lr_states(self):
        # This comes from page 37 of http://digital.cs.usu.edu/~allan/Compilers/Notes/LRParsing.pdf
        g = AssemblyGrammar()
        Ep = AssemblyNonTerminal("E'")
        E = AssemblyNonTerminal("E")
        T = AssemblyNonTerminal("T")
        F = AssemblyNonTerminal("F")

        g.add_production(Ep, [E])
        g.add_production(E, [E, "+", T], [T])

        out = print_stream() if self.tracing else null_output()
        parser = Parser(g)
        parser.print_lr0_states(out)

    def test_lalr_with_epsilon(self):
        # This comes from http://web.cs.dal.ca/~sjackson/lalr1.html
        g = AssemblyGrammar()

        S = AssemblyNonTerminal("S")
        N = AssemblyNonTerminal("N")

        g.add_production(S, [list(), N])

    def test_lists_from_arm(self):
        # Do the test
        pass

class Parser:
    def __init__(self, grammar):
        self.grammar = grammar
        self.states = []
        self.transitions = {}
        self.general_first_follow = None
        self.extended_grammar = None
        self.mergers = []

    def print_lr0_states(self, out=None):
        if not hasattr(out, "write"):
            return

    # ... and so on for the rest of your test methods ...

class FirstFollow:
    pass

def null_output():
    return PrintStream(new NullOutputStream())

def print_stream():
    return System.out
```

Please note that I've used Python's built-in `list` type to represent lists, instead of creating a separate class.