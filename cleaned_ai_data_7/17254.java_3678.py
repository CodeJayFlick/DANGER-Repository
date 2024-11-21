class DropTriggerOperator:
    def __init__(self):
        self.operator_type = "DROP_TRIGGER"

    def set_trigger_name(self, trigger_name: str) -> None:
        self.trigger_name = trigger_name

    def get_trigger_name(self) -> str:
        return self.trigger_name

    def generate_physical_plan(self, generator) -> object:
        try:
            return DropTriggerPlan(self.trigger_name)
        except Exception as e:
            raise QueryProcessException(str(e))
