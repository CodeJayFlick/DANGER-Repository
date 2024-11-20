Here is the translation of the Java code to Python:
```
import query_process_exception as QueryProcessException
from metadata import PartialPath
from physical_plan import PhysicalPlan
from show_plan import ShowContentType
from show_storage_group_plan import ShowStorageGroupPlan
from physical_generator import PhysicalGenerator

class ShowStorageGroupOperator(ShowOperator):
    def __init__(self, token_int_type: int, path: PartialPath) -> None:
        super().__init__(token_int_type)
        self.path = path

    @property
    def path(self) -> PartialPath:
        return self._path

    def generate_physical_plan(self, generator: PhysicalGenerator) -> PhysicalPlan:
        try:
            return ShowStorageGroupPlan(ShowContentType.STORAGE_GROUP, self.path)
        except QueryProcessException as e:
            raise e
```
Note that I've used the `query_process_exception` module to import the equivalent of Java's `QueryProcessException`, and similarly for other modules. Additionally, Python does not have a direct equivalent of Java's `@Override` annotation, so I've simply omitted it.

Also, in Python, we don't need to explicitly define getters and setters like we do in Java. Instead, we can use the `@property` decorator to create read-only properties (in this case, just for the `path` attribute).