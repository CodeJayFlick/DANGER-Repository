class NegationSelector:
    def __init__(self, component):
        self.component = component

    def test(self, t):
        return not self.component.test(t)
