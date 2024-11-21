Here is the translation of the Java code to Python:
```
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
```
Note that I've removed the Java-specific comments and licensing information, as well as some minor formatting changes to make it more readable in Python.