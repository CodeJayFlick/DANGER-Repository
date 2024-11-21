class CreateSnapshotOperator:
    def __init__(self):
        self.operator_type = "CREATE_SCHEMA_SNAPSHOT"

    def generate_physical_plan(self) -> object:
        return {"type": "CreateSnapshotPlan"}
