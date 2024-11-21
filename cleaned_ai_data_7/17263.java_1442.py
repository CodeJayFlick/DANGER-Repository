class SetSystemModeOperator:
    def __init__(self, token_int_type: int, is_read_only: bool):
        self.is_read_only = is_read_only
        super().__init__(token_int_type)
        self.operator_type = "SET_SYSTEM_MODE"

    @property
    def is_read_only(self) -> bool:
        return self._is_read_only

    def generate_physical_plan(self, generator: PhysicalGenerator) -> PhysicalPlan:
        try:
            return SetSystemModePlan(is_read_only=self.is_read_only)
        except QueryProcessException as e:
            raise e
