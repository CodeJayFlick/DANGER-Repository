class DamageCauseExpression:
    def __init__(self):
        self.expression_type = "SIMPLE"

    @property
    def name(self):
        return "Damage Cause"

    @property
    def description(self):
        return "The damage cause of a damage event. Please click on the link for more information."

    @property
    def examples(self):
        return ["damage cause is lava, fire or burning"]

    @property
    def since(self):
        return "2.0"

def register_expression():
    pass

register_expression()

class EventValueExpression:
    def __init__(self, event_type):
        self.event_type = event_type

    def to_string(self, e, debug=False):
        if not isinstance(e, type(None)):
            return f"the damage cause"
        else:
            return "unknown"

# Usage
damage_cause_expression = DamageCauseExpression()
print(damage_cause_expression.name)
print(damage_cause_expression.description)
print(damage_cause_expression.examples)
print(damage_cause_expression.since)

register_expression()

event_value_expression = EventValueExpression(DamageCause)
print(event_value_expression.to_string(None, debug=False))
