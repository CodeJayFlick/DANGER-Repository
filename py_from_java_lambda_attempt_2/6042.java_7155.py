Here is the equivalent Python code:

```Python
class CompareFunctionsTestUtility:
    def __init__(self):
        pass

    @staticmethod
    def check_source_functions(provider, *functions):
        funcs = set(functions)
        fcs = provider.model.get_source_functions()
        assert len(fcs) == len(funcs), "Source functions do not match"
        for func in funcs:
            assert func in fcs, "Function {} is missing".format(func)

    @staticmethod
    def check_target_functions(provider, source, *targets):
        targets_as_list = set(targets)
        tgts = provider.model.get_target_functions(source)
        assert len(tgts) == len(targets_as_list), "Target functions do not match"
        for target in targets_as_list:
            assert target in tgts, "Function {} is missing".format(target)

    @staticmethod
    def get_functions_as_set(*functions):
        return set(functions)

    @staticmethod
    def get_functions_as_map(source, *targets):
        target_set = CompareFunctionsTestUtility.get_functions_as_set(targets)
        return {source: target_set}
```

Note that Python does not have a direct equivalent to Java's `HashSet` or `HashMap`. Instead, we use the built-in set and dictionary types. The `assert` statement is used for assertions in Python, similar to JUnit tests in Java.