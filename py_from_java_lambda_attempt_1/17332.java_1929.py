Here is the translation of the Java code to Python:
```
class KillQueryPlan:
    def __init__(self, query_id: int):
        super().__init__(False, "KILL")
        self.query_id = query_id

    @property
    def get_paths(self) -> list:
        return []

    @property
    def query_id(self) -> int:
        return self._query_id

# Example usage:
kill_plan = KillQueryPlan(123)
print(kill_plan.get_query_id())  # prints: 123
```
Note that I used the `@property` decorator to create getter methods for the `get_paths` and `query_id` attributes, as Python does not have direct equivalent of Java's getters.