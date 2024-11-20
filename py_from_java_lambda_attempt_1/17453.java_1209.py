Here is the translation of the Java code to Python:
```
import os
from typing import List

class ExternalSortJob:
    def __init__(self, part_list: List):
        self.part_list = part_list

    def execute_for_i_point_reader(self) -> List:
        readers = []
        for part in self.part_list:
            readers.append(part.execute_for_i_point_reader())
        return readers


# Example usage
part_list = [...]  # replace with your list of ExternalSortJobPart objects
job = ExternalSortJob(part_list)
readers = job.execute_for_i_point_reader()
```
Note that I've used the `typing` module to define the type hints for the `ExternalSortJob` class and its methods. This is not strictly necessary, but it can help with code readability and maintainability.

Also, I've replaced the Java-specific imports (e.g., `java.io.IOException`) with Python's built-in modules (e.g., `os`). If you need to use any specific libraries or modules in your Python code, please let me know!