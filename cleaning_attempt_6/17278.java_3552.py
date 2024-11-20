class StartTriggerOperator:
    def __init__(self, token_int_type):
        self.trigger_name = None
        super().__init__(token_int_type)
        self.operator_type = "START_TRIGGER"

    @property
    def trigger_name(self):
        return self._trigger_name

    @trigger_name.setter
    def trigger_name(self, value):
        self._trigger_name = value

    def generate_physical_plan(self, generator) -> PhysicalPlan:
        try:
            return StartTriggerPlan(self.trigger_name)
        except Exception as e:
            raise QueryProcessException(str(e))

class PhysicalPlan:
    pass  # abstract class in Python, no implementation needed

class StartTriggerPlan(PhysicalPlan):
    def __init__(self, trigger_name: str):
        self.trigger_name = trigger_name
