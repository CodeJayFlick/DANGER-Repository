class Constraint:
    def __init__(self, name):
        self.name = name

    @property
    def name(self):
        return self._name

    def is_satisfied(self, t):
        raise NotImplementedError("Subclasses must implement this method")

    def load_constraint_data(self, data):
        raise NotImplementedError("Subclasses must implement this method")

    def __eq__(self, obj):
        if not isinstance(obj, Constraint):
            return False
        return self.name == obj.name

    def get_description(self):
        raise NotImplementedError("Subclasses must implement this method")
