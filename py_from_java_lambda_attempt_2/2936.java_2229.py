Here is the translation of the Java code to Python:
```python
class SampleSearcher:
    def __init__(self, program):
        self.program = program

    def search(self, accumulator, monitor):
        it = self.program.get_function_manager().get_functions(True)
        monitor.initialize(len(it))
        while it.has_next():
            if monitor.is_cancelled():
                break
            fun = it.next()
            monitor.increment_progress(1)
            if fun.get_parameter_count() == 0:
                accumulator.add(SearchResults(fun.get_entry_point(), fun.get_name()))

    def get_program(self):
        return self.program

class SearchResults:
    def __init__(self, entry_point, name):
        self.entry_point = entry_point
        self.name = name
```
Note that I've used Python's built-in `list` type to represent the accumulator and function iterator. The rest of the code is straightforward translation from Java to Python.

Also, please note that this code assumes you have a way to interact with the Ghidra API in Python (e.g., using ctypes or another binding). If not, you may need to modify the code accordingly.