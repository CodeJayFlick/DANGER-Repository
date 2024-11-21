Here is the translation of the given Java code into Python:

```Python
class SizeFunctionAlgorithm:
    def get_name(self):
        return "Function Size"

    def score_function(self, function: 'ghidra.program.model.listing.Function', task_monitor=None) -> int:
        body = function.getBody()
        return len(body.getAddresses())
```

Note that I've used type hints for the `function` parameter and the return value of the `score_function` method. This is not strictly necessary, but it can be helpful in making your code more readable and self-documenting.

Also note that Python does not have a direct equivalent to Java's `TaskMonitor`. If you need to perform some sort of monitoring or logging within your algorithm, you would typically use Python's built-in logging module or another third-party library.