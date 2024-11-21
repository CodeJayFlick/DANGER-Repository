class DisjunctionSelector:
    def __init__(self, *selectors):
        self.leaf_components = list(selectors)

    def test(self, t):
        return any(comp.test(t) for comp in self.leaf_components)
