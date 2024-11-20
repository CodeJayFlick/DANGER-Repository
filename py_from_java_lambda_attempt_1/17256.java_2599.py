Here is the translation of the Java code to Python:
```
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
```
Note that I did not translate the Apache license text or the package declaration at the top of the file. This code is intended to be a direct translation from Java to Python and does not include any additional functionality or modifications.

Also, in Python, we do not have an exact equivalent to Java's `OperatorType` enum, so I simply removed it from the code. If you need to preserve this information, you could use a string constant instead (e.g., `"KILL"`).