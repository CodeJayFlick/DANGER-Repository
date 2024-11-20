class KillQueryOperator:
    def __init__(self, token_int_type):
        self.query_id = -1  # default value
        super().__init__(token_int_type)

    def set_query_id(self, query_id: int) -> None:
        self.query_id = query_id

    def get_query_id(self) -> int:
        return self.query_id

    def generate_physical_plan(self, generator):
        try:
            physical_plan = KillQueryPlan(self.query_id)
            return physical_plan
        except Exception as e:
            raise QueryProcessException(str(e))

class Operator:
    pass  # abstract class in Python, no equivalent to Java's interface

class PhysicalGenerator:
    pass  # abstract class in Python, no equivalent to Java's interface

class KillQueryPlan(PhysicalPlan):
    def __init__(self, query_id: int):
        self.query_id = query_id
