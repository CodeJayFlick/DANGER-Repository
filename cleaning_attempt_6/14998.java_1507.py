class AbstractSelector(metaclass=abc.ABCMeta):
    @abstractmethod
    def evaluate(self, item) -> bool:
        pass


class ConjunctionSelector(AbstractSelector):
    def __init__(self, left: 'ConjunctionSelector', right: 'AbstractSelector'):
        self.left = left
        self.right = right

    def evaluate(self, item) -> bool:
        return self.left.evaluate(item) and self.right.evaluate(item)


class DisjunctionSelector(AbstractSelector):
    def __init__(self, left: 'DisjunctionSelector', right: 'AbstractSelector'):
        self.left = left
        self.right = right

    def evaluate(self, item) -> bool:
        return self.left.evaluate(item) or self.right.evaluate(item)


class NegationSelector(AbstractSelector):
    def __init__(self, selector: 'NegationSelector'):
        self.selector = selector

    def evaluate(self, item) -> bool:
        return not self.selector.evaluate(item)
