class StopTriggerOperator:
    def __init__(self, token_int_type):
        self.trigger_name = None
        super().__init__(token_int_type)
        self.operator_type = "STOP_TRIGGER"

    @property
    def trigger_name(self):
        return self._trigger_name

    @trigger_name.setter
    def trigger_name(self, value):
        self._trigger_name = value

    def generate_physical_plan(self, generator) -> PhysicalPlan:
        from . import StopTriggerPlan  # assuming this is in a separate file
        try:
            return StopTriggerPlan(self.trigger_name)
        except Exception as e:
            raise QueryProcessException(str(e))

class PhysicalGenerator:
    pass

class PhysicalPlan:
    pass

class QueryProcessException(Exception):
    pass
