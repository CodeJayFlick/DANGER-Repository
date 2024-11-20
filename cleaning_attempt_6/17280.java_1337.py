class TracingOperator:
    def __init__(self, token_int_type: int, tracing_on: bool):
        self.is_tracing_on = tracing_on
        super().__init__(token_int_type)
        self.operator_type = "TRACING"

    @property
    def is_tracing_on(self) -> bool:
        return self._is_tracing_on

    def generate_physical_plan(self, generator: PhysicalGenerator) -> PhysicalPlan:
        try:
            return TracingPlan(self.is_tracing_on)
        except QueryProcessException as e:
            raise e


class PhysicalGenerator:
    pass  # Not implemented in the original Java code


class PhysicalPlan:
    pass  # Not implemented in the original Java code


class TracingPlan(PhysicalPlan):
    def __init__(self, tracing_on: bool):
        self.tracing_on = tracing_on
