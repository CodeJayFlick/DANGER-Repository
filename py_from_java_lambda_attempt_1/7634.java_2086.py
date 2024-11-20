Here is the translation of the Java code to Python:
```
class HashMatch:
    def __init__(self, function_record: 'ghidra.feature.fid.db.FunctionRecord',
                 primary_function_code_unit_score: float,
                 primary_function_match_mode: 'ghidra.feature.fid.plugin.HashLookupListMode',
                 child_function_code_unit_score: float,
                 parent_function_code_unit_score: float):
        self.function_record = function_record
        self.primary_function_code_unit_score = primary_function_code_unit_score
        self.primary_function_match_mode = primary_function_match_mode
        self.child_function_code_unit_score = child_function_code_unit_score
        self.parent_function_code_unit_score = parent_function_code_unit_score

    def get_function_record(self):
        return self.function_record

    def get_primary_function_code_unit_score(self):
        return self.primary_function_code_unit_score

    def get_primary_function_match_mode(self):
        return self.primary_function_match_mode

    def get_child_function_code_unit_score(self):
        return self.child_function_code_unit_score

    def get_parent_function_code_unit_score(self):
        return self.parent_function_code_unit_score

    def __str__(self):
        overall_score = self.get_primary_function_code_unit_score() + \
                         self.get_child_function_code_unit_score() + \
                         self.get_parent_function_code_unit_score()
        return f"{overall_score:.1f} - {self.primary_function_code_unit_score:.1f} ({self.primary_function_match_mode})/{self.child_function_code_unit_score:.1f}/{self.parent_function_code_unit_score:.1f} {self.function_record.__str__()}"
```
Note that I've used Python's type hinting system to indicate the types of the variables and method parameters. This is not strictly necessary, but it can help with code readability and maintainability.

Also, I've assumed that `ghidra.feature.fid.db.FunctionRecord` and `ghidra.feature.fid.plugin.HashLookupListMode` are Python classes or modules that you have imported elsewhere in your code. If these are actually Java classes or interfaces, you will need to use a library like Jython or Py4J to interact with them from Python.

Finally, I've used the `__str__()` method instead of `toString()`, since this is the standard way to implement string representation in Python.