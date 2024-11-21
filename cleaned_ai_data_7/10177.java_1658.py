class RootDecisionNode:
    def __init__(self):
        super().__init__(DummyConstraint(), None)

    def get_decision_path(self):
        return []

class DummyConstraint:
    def __init__(self):
        pass

    def is_satisfied(self, t):
        return True

    def load_constraint_data(self, data):
        # nothing to load
        pass

    def __eq__(self, obj):
        return self == obj

    def get_description(self):
        return None


class DecisionNode:
    def __init__(self, constraint, parent=None):
        self.constraint = constraint
        self.parent = parent

    def get_decision_path(self):
        # to be implemented in subclasses
        pass
