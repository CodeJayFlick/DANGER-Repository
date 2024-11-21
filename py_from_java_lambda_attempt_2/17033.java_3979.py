Here is the translation of the Java code to Python:
```
class TsFileProcessorInfo:
    def __init__(self, storage_group_info):
        self.storage_group_info = storage_group_info
        self.mem_cost = 0

    def add_tsp_mem_cost(self, cost):
        self.mem_cost += cost
        self.storage_group_info.add_storage_group_mem_cost(cost)

    def release_tsp_mem_cost(self, cost):
        self.storage_group_info.release_storage_group_mem_cost(cost)
        self.mem_cost -= cost

    def clear(self):
        self.storage_group_info.release_storage_group_mem_cost(self.mem_cost)
        self.mem_cost = 0
```
Note that I've used Python's built-in `class` syntax to define a class, and the same naming conventions as in Java. The methods are defined using the `def` keyword, and the code is otherwise equivalent to the original Java code.

I hope this helps! Let me know if you have any questions or need further assistance.