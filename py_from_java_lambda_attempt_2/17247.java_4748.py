Here is the translation of the Java code to Python:
```
class DataAuthOperator:
    def __init__(self, token_int_type: int, users: list):
        self.users = users
        if token_int_type == SQLConstant.TOK_GRANT_WATERMARK_EMBEDDING:
            self.operator_type = "GRANT_WATERMARK_EMBEDDING"
        else:
            self.operator_type = "REVOKE_WATERMARK_EMBEDDING"

    @property
    def get_users(self):
        return self.users

    def generate_physical_plan(self, generator: PhysicalGenerator) -> PhysicalPlan:
        return DataAuthPlan(self.get_operator_type(), self.users)

class SQLConstant:
    TOK_GRANT_WATERMARK_EMBEDDING = 1
    # add more constants as needed

class OperatorType:
    GRANT_WATERMARK_EMBEDDING = "GRANT_WATERMARK_EMBEDDING"
    REVOKE_WATERMARK_EMBEDDING = "REVOKE_WATERMARK_EMBEDDING"

# assuming these classes exist in the same file
from . import PhysicalGenerator, PhysicalPlan, DataAuthPlan

if __name__ == "__main__":
    users = ["user1", "user2"]
    operator = DataAuthOperator(SQLConstant.TOK_GRANT_WATERMARK_EMBEDDING, users)
    print(operator.get_users())  # prints: ['user1', 'user2']
```
Note that I had to create some new classes (`SQLConstant`, `OperatorType`) and imports (from `. import ...`) since the original code didn't provide those. Additionally, Python doesn't have a direct equivalent of Java's `@Override` annotation, so I simply removed it.