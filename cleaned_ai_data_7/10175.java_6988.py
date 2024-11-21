class DecisionSet:
    def __init__(self, property_name):
        self.property_name = property_name
        self.decisions = []

    def get_decisions(self):
        return self.decisions

    def get_values(self):
        values = []
        for decision in self.decisions:
            values.append(decision.value)
        return values

    def get_decision_property_name(self):
        return self.property_name

    def add_decision(self, decision):
        self.decisions.append(decision)

    def is_empty(self):
        return len(self.decisions) == 0
