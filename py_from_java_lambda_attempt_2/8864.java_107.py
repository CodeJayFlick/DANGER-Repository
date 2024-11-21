Here is the translation of the Java code to Python:
```python
import ghidra_program_model_address as AddressSetView
from ghidra_program_model_listing import *
from ghidra_util_task import TaskMonitor

class VTFunctionSizeUtil:
    def __init__(self):
        pass  # non-instantiable

    @staticmethod
    def minimum_size_function_filter(program, original_address_set, min_func_size, monitor):
        result = set(original_address_set)
        for function in program.get_functions(original_address_set, True):
            if monitor.is_cancelled():
                break
            body = function.getBody()
            if function.is_thunk() or len(body) < min_func_size:
                address_ranges = list(body.getAddressRanges())
                for addr_range in address_ranges:
                    result.discard(addr_range)
        return set(result)

# Example usage:
program = ...  # assume you have a Program object
original_address_set = ...  # assume you have an AddressSetView object
min_func_size = 10  # example minimum function size
monitor = TaskMonitor()  # assume you have a TaskMonitor object

result = VTFunctionSizeUtil.minimum_size_function_filter(program, original_address_set, min_func_size, monitor)
print(result)  # print the filtered result
```
Note that I used Python's built-in `set` data structure to represent an address set view. In Java, this is represented by a custom class (`AddressSetView`) which wraps around a `HashSet<AddressRange>`.