class ShowMergeStatusOperator:
    def __init__(self):
        self.operator_type = "SHOW_MERGE_STATUS"

    def generate_physical_plan(self) -> dict:
        return {"physical_plan": {}}
