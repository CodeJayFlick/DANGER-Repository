class AssemblyParseTreeNode:
    def __init__(self, grammar):
        self.parent = None
        self.grammar = grammar

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, value):
        self._parent = value

    def get_sym(self):
        raise NotImplementedError("Subclass must implement this method")

    def generate_string(self):
        raise NotImplementedError("Subclass must implement this method")


class AssemblyGrammar:
    pass


def print_node(out, node, indent=""):
    if hasattr(node, "print"):
        node.print(out, indent)
    else:
        out.write(indent + str(type(node)) + "\n")
